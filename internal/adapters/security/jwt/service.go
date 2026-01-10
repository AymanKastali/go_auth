package jwt

import (
	"crypto/rsa"
	"fmt"
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/dto"
	"go_auth/internal/core/application/ports"
	"go_auth/internal/core/domain/valueobjects"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var defaultSigningMethod = jwt.SigningMethodRS256

type jwtService struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	issuer     string
	audience   string
	accessTTL  time.Duration
	refreshTTL time.Duration
	signingAlg jwt.SigningMethod
}

var _ ports.TokenServicePort = (*jwtService)(nil)

func NewJWTService(cfg *JWTConfig) ports.TokenServicePort {
	return &jwtService{
		privateKey: cfg.PrivateKey(),
		publicKey:  cfg.PublicKey(),
		issuer:     cfg.Issuer(),
		audience:   cfg.Audience(),
		accessTTL:  cfg.AccessTTL(),
		refreshTTL: cfg.RefreshTTL(),
		signingAlg: defaultSigningMethod,
	}
}

// --- Issue Tokens ---

func (s *jwtService) IssueAccessToken(userID, deviceID string, roles []string) (valueobjects.JWTToken, dto.AccessTokenClaims, error) {
	claims := AccessTokenClaims{
		Type:             TokenTypeAccess,
		Roles:            roles,
		DeviceID:         deviceID,
		RegisteredClaims: s.newRegisteredClaims(userID, s.accessTTL),
	}

	token, err := s.sign(claims)
	if err != nil {
		return valueobjects.JWTToken{}, dto.AccessTokenClaims{}, apperr.NewInternalErr("failed to sign access token")
	}

	return token, s.toAccessTokenDTO(claims), nil
}

func (s *jwtService) IssueRefreshToken(userID, deviceID string) (valueobjects.JWTToken, dto.RefreshTokenClaims, error) {
	claims := RefreshTokenClaims{
		Type:             TokenTypeRefresh,
		DeviceID:         deviceID,
		RegisteredClaims: s.newRegisteredClaims(userID, s.refreshTTL),
	}

	token, err := s.sign(claims)
	if err != nil {
		return valueobjects.JWTToken{}, dto.RefreshTokenClaims{}, apperr.NewInternalErr("failed to sign refresh token")
	}

	return token, s.toRefreshTokenDTO(claims), nil
}

// --- Validate Tokens ---

func (s *jwtService) ValidateAccessToken(tokenStr string) (*dto.AccessTokenClaims, error) {
	claims := &AccessTokenClaims{}
	if err := s.parse(tokenStr, claims, TokenTypeAccess); err != nil {
		return nil, apperr.NewUnauthorizedErr(fmt.Sprintf("access token invalid: %v", err))
	}
	dtoClaims := s.toAccessTokenDTO(*claims)
	return &dtoClaims, nil
}

func (s *jwtService) ValidateRefreshToken(tokenStr string) (*dto.RefreshTokenClaims, error) {
	claims := &RefreshTokenClaims{}
	if err := s.parse(tokenStr, claims, TokenTypeRefresh); err != nil {
		return nil, apperr.NewUnauthorizedErr(fmt.Sprintf("refresh token invalid: %v", err))
	}
	dtoClaims := s.toRefreshTokenDTO(*claims)
	return &dtoClaims, nil
}

// --- Internal Helpers ---

func (s *jwtService) newRegisteredClaims(userID string, ttl time.Duration) jwt.RegisteredClaims {
	now := time.Now().UTC()
	return jwt.RegisteredClaims{
		Issuer:    s.issuer,
		Subject:   userID,
		Audience:  []string{s.audience},
		ID:        valueobjects.NewTokenID().String(),
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
	}
}

func (s *jwtService) sign(claims jwt.Claims) (valueobjects.JWTToken, error) {
	token := jwt.NewWithClaims(s.signingAlg, claims)
	signed, err := token.SignedString(s.privateKey)
	if err != nil {
		return valueobjects.JWTToken{}, err
	}
	return valueobjects.NewJWTToken(signed), nil
}

func (s *jwtService) parse(tokenStr string, claims jwt.Claims, expectedType string) error {
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, ErrUnexpectedMethod
		}
		return s.publicKey, nil
	})

	if err != nil {
		return err
	}

	if !token.Valid {
		return ErrInvalidToken
	}

	// Check if the claims implementation provides a GetType method
	if c, ok := claims.(interface{ GetType() string }); ok {
		if c.GetType() != expectedType {
			return ErrTypeMismatch
		}
	}

	return nil
}

// --- Mappers ---

func (s *jwtService) toAccessTokenDTO(c AccessTokenClaims) dto.AccessTokenClaims {
	return dto.AccessTokenClaims{
		Issuer:    c.Issuer,
		Subject:   c.Subject,
		DeviceID:  c.DeviceID,
		Audience:  c.Audience,
		ExpiresAt: c.ExpiresAt.Time,
		IssuedAt:  c.IssuedAt.Time,
		NotBefore: c.NotBefore.Time,
		JTI:       c.ID,
		Type:      c.Type,
		Roles:     c.Roles,
	}
}

func (s *jwtService) toRefreshTokenDTO(c RefreshTokenClaims) dto.RefreshTokenClaims {
	return dto.RefreshTokenClaims{
		Issuer:    c.Issuer,
		Subject:   c.Subject,
		DeviceID:  c.DeviceID,
		Audience:  c.Audience,
		ExpiresAt: c.ExpiresAt.Time,
		IssuedAt:  c.IssuedAt.Time,
		NotBefore: c.NotBefore.Time,
		JTI:       c.ID,
		Type:      c.Type,
	}
}
