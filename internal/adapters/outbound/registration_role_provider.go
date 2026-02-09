package outbound

import (
	"context"
	"go_auth/internal/domain"
)

type registrationRoleProvider struct {
	roleRepo domain.IRoleRepository
}

func NewRegistrationRoleProvider(roleRepo domain.IRoleRepository) domain.IRegistrationRoleProvider {
	return &registrationRoleProvider{roleRepo: roleRepo}
}

func (p *registrationRoleProvider) DefaultMemberRole(ctx context.Context) (domain.RoleName, error) {
	name, err := domain.NewRoleName("member")
	if err != nil {
		return domain.ZeroRoleName, err
	}
	role, err := p.roleRepo.FindByName(ctx, name)
	if err != nil {
		return domain.ZeroRoleName, err
	}
	if role == nil {
		return domain.ZeroRoleName, domain.ErrRoleNotFound
	}
	return role.Name(), nil
}

func (p *registrationRoleProvider) DefaultAdminRole(ctx context.Context) (domain.RoleName, error) {
	name, err := domain.NewRoleName("super_admin")
	if err != nil {
		return domain.ZeroRoleName, err
	}
	role, err := p.roleRepo.FindByName(ctx, name)
	if err != nil {
		return domain.ZeroRoleName, err
	}
	if role == nil {
		return domain.ZeroRoleName, domain.ErrRoleNotFound
	}
	return role.Name(), nil
}
