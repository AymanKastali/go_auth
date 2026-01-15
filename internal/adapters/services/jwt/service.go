package jwt

import (
	"crypto/rsa"
	"errors"
	"go_auth/internal/core/application/dto"
	"go_auth/internal/core/application/ports"
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

var _ ports.ITokenService = (*jwtService)(nil)

func NewJWTService(cfg *JWTConfig) ports.ITokenService {
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
	currentTime time.Time,
) (valueobjects.Token, dto.AccessTokenClaims, error) {
	claims := AccessTokenClaims{
		Type:             TokenTypeAccess,
		Roles:            roles,
		DeviceID:         deviceID,
		RegisteredClaims: s.newRegisteredClaims(tokenID, userID, s.accessTTL, currentTime),
	}

	token, err := s.sign(claims)
	if err != nil {
		// Internal infrastructure failure
		return valueobjects.Token{}, dto.AccessTokenClaims{}, err
	}

	return token, s.mapToAccessDTO(claims), nil
}

func (s *jwtService) IssueRefreshToken(
	tokenID, userID, deviceID string,
	currentTime time.Time,
) (valueobjects.Token, dto.RefreshTokenClaims, error) {
	claims := RefreshTokenClaims{
		Type:             TokenTypeRefresh,
		DeviceID:         deviceID,
		RegisteredClaims: s.newRegisteredClaims(tokenID, userID, s.refreshTTL, currentTime),
	}

	token, err := s.sign(claims)
	if err != nil {
		return valueobjects.Token{}, dto.RefreshTokenClaims{}, err
	}

	return token, s.mapToRefreshDTO(claims), nil
}

func (s *jwtService) ValidateAccessToken(tokenStr string) (*dto.AccessTokenClaims, error) {
	claims := &AccessTokenClaims{}
	err := s.parse(tokenStr, claims, TokenTypeAccess)
	if err == nil {
		dto := s.mapToAccessDTO(*claims)
		return &dto, nil
	}

	return nil, s.mapJWTErr(err)
}

func (s *jwtService) ValidateRefreshToken(tokenStr string) (*dto.RefreshTokenClaims, error) {
	claims := &RefreshTokenClaims{}
	err := s.parse(tokenStr, claims, TokenTypeRefresh)
	if err == nil {
		dto := s.mapToRefreshDTO(*claims)
		return &dto, nil
	}

	return nil, s.mapJWTErr(err)
}

// mapJWTErr centralizes the translation from jwt-v5 errors to your Domain Errors
func (s *jwtService) mapJWTErr(err error) error {
	if err == nil {
		return nil
	}

	// 1. Handle Expiration
	if errors.Is(err, jwt.ErrTokenExpired) {
		return WrapExpired(err, "token has expired")
	}

	// 2. Handle Signature/Format/Claims issues
	if errors.Is(err, jwt.ErrTokenSignatureInvalid) ||
		errors.Is(err, jwt.ErrTokenMalformed) ||
		errors.Is(err, jwt.ErrTokenUnverifiable) ||
		errors.Is(err, jwt.ErrTokenInvalidClaims) ||
		errors.Is(err, jwt.ErrTokenRequiredClaimMissing) {
		return WrapInvalid(err, "token is invalid or tampered")
	}

	// 3. Technical failures (e.g., RSA key issues)
	// Return raw so they trigger a 500 Internal error
	return err
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

func (s *jwtService) newRegisteredClaims(tokenID, userID string, ttl time.Duration, currentTime time.Time) jwt.RegisteredClaims {
	return jwt.RegisteredClaims{
		Issuer:    s.issuer,
		Subject:   userID,
		Audience:  []string{s.audience},
		ID:        tokenID,
		IssuedAt:  jwt.NewNumericDate(currentTime),
		NotBefore: jwt.NewNumericDate(currentTime),
		ExpiresAt: jwt.NewNumericDate(currentTime.Add(ttl)),
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
