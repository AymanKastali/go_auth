package security

import (
	"go_auth/internal/core/application/dto"
	"go_auth/internal/core/domain/valueobjects"
)

type TokenServicePort interface {
	IssueAccessToken(userID, deviceID string, roles []string) (valueobjects.JWTToken, error)
	IssueRefreshToken(userID, deviceID string) (valueobjects.JWTToken, error)
	ValidateAccessToken(accessToken string) (*dto.AccessTokenClaimsDto, error)
	ValidateRefreshToken(refreshToken string) (*dto.RefreshTokenClaimsDto, error)
}
