package jwt

import (
	"crypto/rsa"
	"errors"
	"go_auth/internal/core/application/dto"
	"go_auth/internal/core/application/ports"
	"go_auth/internal/core/domain/derr"
	"go_auth/internal/core/domain/valueobjects"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

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
		signingAlg: jwt.SigningMethodRS256,
	}
}

func (s *jwtService) IssueAccessToken(
	tokenID, userID, deviceID string,
	roles []string,
	now time.Time,
) (valueobjects.Token, dto.AccessTokenClaims, error) {
	claims := AccessTokenClaims{
		Type:             TokenTypeAccess,
		Roles:            roles,
		DeviceID:         deviceID,
		RegisteredClaims: s.newRegisteredClaims(tokenID, userID, s.accessTTL, now),
	}

	token, err := s.sign(claims)
	if err != nil {
		return valueobjects.Token{}, dto.AccessTokenClaims{}, derr.NewViolation.Internal("failed to sign access token")
	}

	return token, s.mapToAccessDTO(claims), nil
}

func (s *jwtService) IssueRefreshToken(
	tokenID, userID, deviceID string,
	now time.Time,
) (valueobjects.Token, dto.RefreshTokenClaims, error) {
	claims := RefreshTokenClaims{
		Type:             TokenTypeRefresh,
		DeviceID:         deviceID,
		RegisteredClaims: s.newRegisteredClaims(tokenID, userID, s.refreshTTL, now),
	}

	token, err := s.sign(claims)
	if err != nil {
		return valueobjects.Token{}, dto.RefreshTokenClaims{}, derr.NewViolation.Internal("failed to sign refresh token")
	}

	return token, s.mapToRefreshDTO(claims), nil
}

func (s *jwtService) ValidateAccessToken(tokenStr string) (*dto.AccessTokenClaims, error) {
	if tokenStr == "" {
		return nil, derr.NewValidation.RequiredToken()
	}

	claims := &AccessTokenClaims{}
	err := s.parse(tokenStr, claims, TokenTypeAccess)
	if err == nil {
		dto := s.mapToAccessDTO(*claims)
		return &dto, nil
	}

	if errors.Is(err, jwt.ErrTokenExpired) {
		return nil, derr.NewViolation.TokenExpired()
	}

	if errors.Is(err, jwt.ErrTokenSignatureInvalid) ||
		errors.Is(err, jwt.ErrTokenMalformed) ||
		errors.Is(err, jwt.ErrTokenUnverifiable) ||
		errors.Is(err, jwt.ErrTokenInvalidClaims) ||
		errors.Is(err, jwt.ErrTokenRequiredClaimMissing) {
		return nil, derr.NewViolation.TokenInvalid()
	}

	if errors.Is(err, jwt.ErrInvalidKey) || errors.Is(err, jwt.ErrInvalidKeyType) {
		return nil, derr.NewViolation.Internal("auth service configuration error")
	}

	return nil, derr.NewViolation.TokenInvalid()
}

func (s *jwtService) ValidateRefreshToken(tokenStr string) (*dto.RefreshTokenClaims, error) {
	if tokenStr == "" {
		return nil, derr.NewValidation.RequiredToken()
	}

	claims := &RefreshTokenClaims{}
	err := s.parse(tokenStr, claims, TokenTypeRefresh)
	if err == nil {
		dto := s.mapToRefreshDTO(*claims)
		return &dto, nil
	}

	if errors.Is(err, jwt.ErrTokenExpired) {
		return nil, derr.NewViolation.TokenExpired()
	}

	if errors.Is(err, jwt.ErrTokenSignatureInvalid) ||
		errors.Is(err, jwt.ErrTokenMalformed) ||
		errors.Is(err, jwt.ErrTokenUnverifiable) ||
		errors.Is(err, jwt.ErrTokenInvalidClaims) {
		return nil, derr.NewViolation.TokenInvalid()
	}

	if errors.Is(err, jwt.ErrInvalidKey) || errors.Is(err, jwt.ErrInvalidKeyType) {
		return nil, derr.NewViolation.Internal("refresh service configuration error")
	}

	return nil, derr.NewValidation.RequiredToken()
}

func (s *jwtService) sign(claims jwt.Claims) (valueobjects.Token, error) {
	token := jwt.NewWithClaims(s.signingAlg, claims)
	signed, err := token.SignedString(s.privateKey)
	if err != nil {
		return valueobjects.Token{}, err
	}

	return valueobjects.NewToken(signed)
}

func (s *jwtService) parse(tokenStr string, claims jwt.Claims, expectedType string) error {
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, jwt.ErrInvalidKeyType
		}
		return s.publicKey, nil
	})

	if err != nil {
		return err
	}

	if !token.Valid {
		return jwt.ErrTokenSignatureInvalid
	}

	c, ok := claims.(interface{ GetType() string })
	if !ok {
		return jwt.ErrTokenRequiredClaimMissing
	}

	if c.GetType() != expectedType {
		return jwt.ErrTokenInvalidClaims
	}

	return nil
}

func (s *jwtService) newRegisteredClaims(tokenID, userID string, ttl time.Duration, now time.Time) jwt.RegisteredClaims {
	return jwt.RegisteredClaims{
		Issuer:    s.issuer,
		Subject:   userID,
		Audience:  []string{s.audience},
		ID:        tokenID,
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
	}
}

func (s *jwtService) mapToAccessDTO(c AccessTokenClaims) dto.AccessTokenClaims {
	return dto.AccessTokenClaims{
		Issuer: c.Issuer, Subject: c.Subject, DeviceID: c.DeviceID,
		Audience: c.Audience, ExpiresAt: c.ExpiresAt.Time,
		IssuedAt: c.IssuedAt.Time, JTI: c.ID, Roles: c.Roles,
	}
}

func (s *jwtService) mapToRefreshDTO(c RefreshTokenClaims) dto.RefreshTokenClaims {
	return dto.RefreshTokenClaims{
		Issuer: c.Issuer, Subject: c.Subject, DeviceID: c.DeviceID,
		Audience: c.Audience, ExpiresAt: c.ExpiresAt.Time,
		IssuedAt: c.IssuedAt.Time, JTI: c.ID,
	}
}
