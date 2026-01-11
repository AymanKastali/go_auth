package ports

import (
	"go_auth/internal/core/application/dto"
	"go_auth/internal/core/domain/valueobjects"
	"time"
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
		tokenID, userID, deviceID string,
		roles []string,
		now time.Time,
	) (token valueobjects.Token, claims dto.AccessTokenClaims, err error)
	IssueRefreshToken(
		tokenID, userID, deviceID string,
		now time.Time,
	) (token valueobjects.Token, claims dto.RefreshTokenClaims, err error)
	ValidateAccessToken(token string) (*dto.AccessTokenClaims, error)
	ValidateRefreshToken(token string) (*dto.RefreshTokenClaims, error)
}
