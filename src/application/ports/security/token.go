package security

import (
	"go_auth/src/application/dto"
	"go_auth/src/domain/value_objects"
)

type TokenServicePort interface {
	IssueAccessToken(
		userID string,
		roles []string,
	) (value_objects.JWTToken, error)
	IssueRefreshToken(userID string) (value_objects.JWTToken, error)
	ValidateAccessToken(accessToken string) (*dto.AccessTokenClaims, error)
	ValidateRefreshToken(refreshToken string) (*dto.RefreshTokenClaims, error)
}
