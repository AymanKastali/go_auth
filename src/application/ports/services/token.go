package services

import (
	valueobjects "go_auth/src/domain/value_objects"
	"go_auth/src/infra/services/jwt"
)

type TokenServicePort interface {
	IssueAccessToken(userID string) (valueobjects.JWTToken, error)
	IssueRefreshToken(userID string) (valueobjects.JWTToken, error)
	ValidateAccessToken(token string) (*jwt.AccessTokenClaims, error)
}
