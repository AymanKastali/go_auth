package services

import (
	"go_auth/src/domain/entities"
	valueobjects "go_auth/src/domain/value_objects"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTService struct {
	secret     []byte
	issuer     string
	signingAlg jwt.SigningMethod
	accessTTL  time.Duration
	refreshTTL time.Duration
}

func NewJWTService(secret, issuer string, accessTTL, refreshTTL time.Duration) *JWTService {
	return &JWTService{
		secret:     []byte(secret),
		issuer:     issuer,
		signingAlg: jwt.SigningMethodHS256,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
	}
}

// Implement TokenServicePort interface
func (s *JWTService) IssueAccessToken(user *entities.User) (valueobjects.AccessToken, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": user.ID().Value().String(),
		"iss": s.issuer,
		"iat": now.Unix(),
		"exp": now.Add(s.accessTTL).Unix(),
		"typ": "access",
	}
	token := jwt.NewWithClaims(s.signingAlg, claims)
	signed, err := token.SignedString(s.secret)
	if err != nil {
		return valueobjects.AccessToken{}, err
	}
	return valueobjects.NewAccessToken(signed), nil
}

func (s *JWTService) IssueRefreshToken(user *entities.User) (valueobjects.RefreshToken, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": user.ID().Value().String(),
		"iss": s.issuer,
		"iat": now.Unix(),
		"exp": now.Add(s.refreshTTL).Unix(),
		"typ": "refresh",
	}
	token := jwt.NewWithClaims(s.signingAlg, claims)
	signed, err := token.SignedString(s.secret)
	if err != nil {
		return valueobjects.RefreshToken{}, err
	}
	return valueobjects.NewRefreshToken(signed), nil
}
