package jwt

import (
	"crypto/rsa"
	"fmt"
	"go_auth/src/domain/value_objects"
	"go_auth/src/infra/config"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var SigningMethod = jwt.SigningMethodRS256

type JWTService struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	issuer     string
	audience   string
	accessTTL  time.Duration
	refreshTTL time.Duration
	signingAlg jwt.SigningMethod
}

func NewJWTService(cfg *config.JWTConfig) *JWTService {
	return &JWTService{
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
	organizationID *string,
	roles []string,
) (value_objects.JWTToken, error) {
	now := time.Now()

	claims := AccessTokenClaims{
		UserID:         userID,
		OrganizationID: organizationID,
		Type:           TokenTypeAccess,
		Roles:          roles,
		RegisteredClaims: jwt.RegisteredClaims{
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

func (s *JWTService) ValidateAccessToken(tokenStr string) (*AccessTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &AccessTokenClaims{}, func(t *jwt.Token) (any, error) {
		return s.publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*AccessTokenClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid or expired token")
	}

	return claims, nil
}
