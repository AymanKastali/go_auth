package security

import (
	"go_auth/src/application/dto"
	"go_auth/src/domain/value_objects"
)

type TokenServicePort interface {
	IssueAccessToken(userID, deviceID string, roles []string) (value_objects.JWTToken, error)
	IssueRefreshToken(userID, deviceID string) (value_objects.JWTToken, error)
	ValidateAccessToken(accessToken string) (*dto.AccessTokenClaimsDto, error)
	ValidateRefreshToken(refreshToken string) (*dto.RefreshTokenClaimsDto, error)
}
