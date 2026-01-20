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
	Issue(ctx dto.IssueSessionToken) (dto.IssuedSessionToken, error)
	Validate(raw string) (dto.SessionTokenMetadata, error)
}

// type ISessionRenewalTokenService interface {
// 	Issue(ctx dto.IssueRenewalToken) (dto.IssuedRenewalToken, error)
// 	Rotate(raw string) (dto.IssuedRenewalToken, error)
// 	Revoke(raw string) error
// }
