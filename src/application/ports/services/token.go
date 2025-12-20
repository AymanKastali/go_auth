package services

import (
	"go_auth/src/domain/value_objects"
	"go_auth/src/infra/services/jwt"
)

type TokenServicePort interface {
	IssueAccessToken(
		userID string,
		organizationID *string,
		roles []string,
	) (value_objects.JWTToken, error)
	IssueRefreshToken(userID string) (value_objects.JWTToken, error)
	ValidateAccessToken(token string) (*jwt.AccessTokenClaims, error)
}
