package jwt

import (
	"crypto/rsa"
	"errors"
	"go_auth/internal/core/application/apperr"
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
		// Use the Internal intent for signing failures
		return valueobjects.Token{}, dto.AccessTokenClaims{}, apperr.Internal(err)
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
		return valueobjects.Token{}, dto.RefreshTokenClaims{}, apperr.Internal(err)
	}

	return token, s.mapToRefreshDTO(claims), nil
}

func (s *jwtService) ValidateAccessToken(tokenStr string) (*dto.AccessTokenClaims, error) {
	claims := &AccessTokenClaims{}
	if err := s.parse(tokenStr, claims, TokenTypeAccess); err != nil {
		// Wrap the technical parse error in the Unauthorized intent
		return nil, apperr.Unauthorized(err)
	}
	dto := s.mapToAccessDTO(*claims)
	return &dto, nil
}

func (s *jwtService) ValidateRefreshToken(tokenStr string) (*dto.RefreshTokenClaims, error) {
	claims := &RefreshTokenClaims{}
	if err := s.parse(tokenStr, claims, TokenTypeRefresh); err != nil {
		// Wrap the technical parse error in the Unauthorized intent
		return nil, apperr.Unauthorized(err)
	}
	dto := s.mapToRefreshDTO(*claims)
	return &dto, nil
}

// --- Private Helpers ---

func (s *jwtService) sign(claims jwt.Claims) (valueobjects.Token, error) {
	token := jwt.NewWithClaims(s.signingAlg, claims)
	signed, err := token.SignedString(s.privateKey)
	if err != nil {
		return valueobjects.Token{}, err // Return raw; IssueAccessToken wraps it
	}

	return valueobjects.NewToken(signed)
}

func (s *jwtService) parse(tokenStr string, claims jwt.Claims, expectedType string) error {
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return s.publicKey, nil
	})

	if err != nil {
		return err // Return raw; Validate methods wrap it in Unauthorized
	}

	if !token.Valid {
		return errors.New("token is mathematically invalid")
	}

	if c, ok := claims.(interface{ GetType() string }); ok {
		if c.GetType() != expectedType {
			return errors.New("token type mismatch")
		}
	} else {
		return errors.New("missing token type claim")
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
