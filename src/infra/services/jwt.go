package services

import (
	"context"
	"errors"
	valueobjects "go_auth/src/domain/value_objects"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTService struct {
	secret     []byte
	issuer     string
	signingAlg jwt.SigningMethod
}

func NewJWTService(secret string, issuer string) *JWTService {
	return &JWTService{
		secret:     []byte(secret),
		issuer:     issuer,
		signingAlg: jwt.SigningMethodHS256,
	}
}

func (s *JWTService) GenerateAccessToken(userID valueobjects.UserID, ttl time.Duration) (valueobjects.AccessToken, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": userID.Value().String(),
		"iss": s.issuer,
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
		"typ": "access",
	}
	token := jwt.NewWithClaims(s.signingAlg, claims)
	signed, err := token.SignedString(s.secret)
	if err != nil {
		return valueobjects.AccessToken{}, err
	}
	return valueobjects.NewAccessToken(signed), nil
}

func (s *JWTService) GenerateRefreshToken(userID valueobjects.UserID, ttl time.Duration) (valueobjects.RefreshToken, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": userID.Value().String(),
		"iss": s.issuer,
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
		"typ": "refresh",
	}
	token := jwt.NewWithClaims(s.signingAlg, claims)
	signed, err := token.SignedString(s.secret)
	if err != nil {
		return valueobjects.RefreshToken{}, err
	}
	return valueobjects.NewRefreshToken(signed), nil
}

func (s *JWTService) ParseAndValidateAccessToken(ctx context.Context, tokenStr string) (valueobjects.UserID, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != s.signingAlg.Alg() {
			return nil, errors.New("unexpected signing alg")
		}
		return s.secret, nil
	})
	if err != nil || !token.Valid {
		return valueobjects.UserID{}, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return valueobjects.UserID{}, errors.New("invalid claims")
	}
	sub, ok := claims["sub"].(string)
	if !ok {
		return valueobjects.UserID{}, errors.New("no sub")
	}
	uid, err := valueobjects.UserIDFromString(sub)
	if err != nil {
		return valueobjects.UserID{}, err
	}
	return uid, nil
}
