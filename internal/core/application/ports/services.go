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
	// IssueAccessToken generates a signed access token and returns both the token string and its claims
	IssueAccessToken(userID, deviceID string, roles []string) (token valueobjects.JWTToken, claims dto.AccessTokenClaims, err error)

	// IssueRefreshToken generates a signed refresh token and returns both the token string and its claims
	IssueRefreshToken(userID, deviceID string) (token valueobjects.JWTToken, claims dto.RefreshTokenClaims, err error)

	// ValidateAccessToken parses & validates a signed access token and returns the claims
	ValidateAccessToken(token string) (*dto.AccessTokenClaims, error)

	// ValidateRefreshToken parses & validates a signed refresh token and returns the claims
	ValidateRefreshToken(token string) (*dto.RefreshTokenClaims, error)
}
