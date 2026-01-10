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
	IssueAccessToken(
		userID, deviceID string,
		roles []string,
	) (token valueobjects.JWTToken, claims dto.AccessTokenClaims, err error)
	IssueRefreshToken(
		userID, deviceID string,
	) (token valueobjects.JWTToken, claims dto.RefreshTokenClaims, err error)
	ValidateAccessToken(token string) (*dto.AccessTokenClaims, error)
	ValidateRefreshToken(token string) (*dto.RefreshTokenClaims, error)
}
