package security

import (
	"go_auth/src/domain/value_objects"
	"go_auth/src/infra/security/jwt"
)

type TokenServicePort interface {
	IssueAccessToken(
		userID string,
		roles []string,
	) (value_objects.JWTToken, error)
	IssueRefreshToken(userID string) (value_objects.JWTToken, error)
	ValidateAccessToken(token string) (*jwt.AccessTokenClaims, error)
}
