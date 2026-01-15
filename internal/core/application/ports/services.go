package ports

import (
	"go_auth/internal/core/application/dto"
	"go_auth/internal/core/domain/valueobjects"
	"time"
)

type ISeedAdminService interface {
	SeedAdmin() error
}

type ISeedRolesService interface {
	SeedDefaultRoles() error
}

type ITokenService interface {
	IssueAccessToken(
		tokenID, userID, deviceID string,
		roles []string,
		currentTime time.Time,
	) (token valueobjects.Token, claims dto.AccessTokenClaims, err error)
	IssueRefreshToken(
		tokenID, userID, deviceID string,
		currentTime time.Time,
	) (token valueobjects.Token, claims dto.RefreshTokenClaims, err error)
	ValidateAccessToken(token string) (*dto.AccessTokenClaims, error)
	ValidateRefreshToken(token string) (*dto.RefreshTokenClaims, error)
}
