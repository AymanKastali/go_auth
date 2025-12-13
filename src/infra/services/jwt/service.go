package jwt

import (
	"crypto/rsa"
	valueobjects "go_auth/src/domain/value_objects"
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
func (s *JWTService) IssueAccessToken(userID string, roles []string) (valueobjects.AccessToken, error) {
	now := time.Now()

	claims := AccessTokenClaims{
		UserID: userID,
		Type:   TokenTypeAccess,
		Roles:  roles,
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
		return valueobjects.AccessToken{}, err
	}

	return valueobjects.NewAccessToken(signed), nil
}

// IssueRefreshToken issues a signed JWT refresh token using typed claims.
func (s *JWTService) IssueRefreshToken(userID string) (valueobjects.RefreshToken, error) {
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
		return valueobjects.NewRefreshToken(signed), err
	}

	return valueobjects.NewRefreshToken(signed), nil
}
