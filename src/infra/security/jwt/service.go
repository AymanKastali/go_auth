package jwt

import (
	"crypto/rsa"
	"fmt"
	"go_auth/src/application/dto"
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
		UserID: userID,
		Type:   TokenTypeAccess,
		Roles:  roles,
		RegisteredClaims: jwt.RegisteredClaims{
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
		UserID: userID,
		Type:   TokenTypeRefresh,
		RegisteredClaims: jwt.RegisteredClaims{
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

func (s *JWTService) ValidateAccessToken(accessToken string) (*dto.AccessTokenClaims, error) {
	token, err := jwt.ParseWithClaims(accessToken, &AccessTokenClaims{}, func(t *jwt.Token) (any, error) {
		return s.publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*AccessTokenClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid or expired token")
	}

	appClaims := &dto.AccessTokenClaims{
		Issuer:   claims.Issuer,
		Subject:  claims.Subject,
		Audience: claims.Audience,
		JTI:      claims.ID,
		UserID:   claims.UserID,
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

func (s *JWTService) ValidateRefreshToken(refreshToken string) (*dto.RefreshTokenClaims, error) {
	token, err := jwt.ParseWithClaims(refreshToken, &AccessTokenClaims{}, func(t *jwt.Token) (any, error) {
		return s.publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*AccessTokenClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid or expired token")
	}

	appClaims := &dto.RefreshTokenClaims{
		Issuer:   claims.Issuer,
		Subject:  claims.Subject,
		Audience: claims.Audience,
		JTI:      claims.ID,
		UserID:   claims.UserID,
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
