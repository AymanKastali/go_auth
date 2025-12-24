package security

import (
	"go_auth/src/application/dto"
	"go_auth/src/domain/value_objects"
)

type TokenServicePort interface {
	IssueAccessToken(
		userId, deviceId string,
		roles []string,
	) (value_objects.JWTToken, error)
	IssueRefreshToken(userId, deviceId string) (value_objects.JWTToken, error)
	ValidateAccessToken(accessToken string) (*dto.AccessTokenClaimsDto, error)
	ValidateRefreshToken(refreshToken string) (*dto.RefreshTokenClaimsDto, error)
}
