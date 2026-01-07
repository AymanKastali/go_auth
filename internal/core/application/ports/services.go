package ports

import (
	"go_auth/internal/core/application/dto"
	"go_auth/internal/core/domain/valueobjects"
)

type SeedAdminServicePort interface {
	SeedAdmin() error
}

type SeedRolesServicePort interface {
	SeedDefaultRoles() error
}

type HashPasswordServicePort interface {
	Hash(raw string) (string, error)
	Compare(raw string, hashed string) bool
}

type TokenServicePort interface {
	IssueAccessToken(userID, deviceID string, roles []string) (valueobjects.JWTToken, error)
	IssueRefreshToken(userID, deviceID string) (valueobjects.JWTToken, error)
	ValidateAccessToken(accessToken string) (*dto.AccessTokenClaimsDto, error)
	ValidateRefreshToken(refreshToken string) (*dto.RefreshTokenClaimsDto, error)
}
