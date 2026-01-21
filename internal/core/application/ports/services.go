package ports

import (
	"go_auth/internal/core/application/dto"
)

type ISeedAdminService interface {
	SeedAdmin() error
}

type ISeedRolesService interface {
	SeedDefaultRoles() error
}

type ISessionTokenIssuerService interface {
	Issue(ctx dto.SessionTokenMetadata) (dto.IssuedSessionToken, error)
	Validate(raw string) (dto.SessionTokenMetadata, error)
}

// type ISessionRefreshTokenService interface {
// 	Issue(ctx dto.IssueRefreshToken) (dto.IssuedRefreshToken, error)
// 	Rotate(raw string) (dto.IssuedRefreshToken, error)
// 	Revoke(raw string) error
// }
