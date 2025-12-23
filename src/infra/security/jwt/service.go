package jwt

import (
	"crypto/rsa"
	"fmt"
	"go_auth/src/application/dto"
	"go_auth/src/domain/errors"
	"go_auth/src/domain/factories"
	"go_auth/src/domain/value_objects"
	"go_auth/src/infra/config"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var SigningMethod = jwt.SigningMethodRS256

type JWTService struct {
	idFactory  factories.IDFactory
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	issuer     string
	audience   string
	accessTTL  time.Duration
	refreshTTL time.Duration
	signingAlg jwt.SigningMethod
}

func NewJWTService(
	cfg *config.JWTConfig,
	idFactory factories.IDFactory,
) *JWTService {
	return &JWTService{
		idFactory:  idFactory,
		privateKey: cfg.PrivateKey,
		publicKey:  cfg.PublicKey,
		issuer:     cfg.Issuer,
		audience:   cfg.Audience,
		accessTTL:  cfg.AccessTTL,
		refreshTTL: cfg.RefreshTTL,
		signingAlg: SigningMethod,
	}
}
func (s *JWTService) IssueAccessToken(
	userID string,
	roles []string,
) (value_objects.JWTToken, error) {
	now := time.Now()

	claims := AccessTokenClaims{
		Type:  TokenTypeAccess,
		Roles: roles,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			ID:        s.idFactory.NewTokenID().Value.String(),
			Issuer:    s.issuer,
			Audience:  []string{s.audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.accessTTL)),
		},
	}

	token := jwt.NewWithClaims(s.signingAlg, claims)
	signed, err := token.SignedString(s.privateKey)
	if err != nil {
		return value_objects.JWTToken{}, err
	}

	return value_objects.JWTToken{Value: signed}, nil
}

func (s *JWTService) IssueRefreshToken(userID string) (value_objects.JWTToken, error) {
	now := time.Now()

	claims := RefreshTokenClaims{
		Type: TokenTypeRefresh,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			ID:        s.idFactory.NewTokenID().Value.String(),
			Issuer:    s.issuer,
			Audience:  []string{s.audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.refreshTTL)),
		},
	}

	token := jwt.NewWithClaims(s.signingAlg, claims)
	signed, err := token.SignedString(s.privateKey)
	if err != nil {
		return value_objects.JWTToken{Value: signed}, err
	}

	return value_objects.JWTToken{Value: signed}, nil
}

func (s *JWTService) ValidateAccessToken(accessToken string) (*dto.AccessTokenClaimsDto, error) {
	token, err := jwt.ParseWithClaims(accessToken, &AccessTokenClaims{}, func(t *jwt.Token) (any, error) {
		// Ensure the signing method is what we expect (RS256)
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*AccessTokenClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid or expired token")
	}

	if claims.Type != TokenTypeAccess {
		return nil, fmt.Errorf("token type mismatch: expected access, got %s", claims.Type)
	}

	appClaims := &dto.AccessTokenClaimsDto{
		Issuer:   claims.Issuer,
		Subject:  claims.Subject,
		Audience: claims.Audience,
		JTI:      claims.ID,
		Type:     claims.Type,
		Roles:    claims.Roles,
	}

	if claims.ExpiresAt != nil {
		appClaims.ExpiresAt = claims.ExpiresAt.Time
	}
	if claims.NotBefore != nil {
		appClaims.NotBefore = claims.NotBefore.Time
	}
	if claims.IssuedAt != nil {
		appClaims.IssuedAt = claims.IssuedAt.Time
	}

	return appClaims, nil
}

func (s *JWTService) ValidateRefreshToken(refreshToken string) (*dto.RefreshTokenClaimsDto, error) {
	token, err := jwt.ParseWithClaims(refreshToken, &RefreshTokenClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.publicKey, nil
	})

	if err != nil {
		return nil, errors.ErrInvalidToken
	}

	claims, ok := token.Claims.(*RefreshTokenClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid or expired token")
	}

	if claims.Type != TokenTypeRefresh {
		return nil, fmt.Errorf("token type mismatch: expected refresh, got %s", claims.Type)
	}

	appClaims := &dto.RefreshTokenClaimsDto{
		Issuer:   claims.Issuer,
		Subject:  claims.Subject,
		Audience: claims.Audience,
		JTI:      claims.ID,
		Type:     claims.Type,
	}

	if claims.ExpiresAt != nil {
		appClaims.ExpiresAt = claims.ExpiresAt.Time
	}
	if claims.NotBefore != nil {
		appClaims.NotBefore = claims.NotBefore.Time
	}
	if claims.IssuedAt != nil {
		appClaims.IssuedAt = claims.IssuedAt.Time
	}

	return appClaims, nil
}
