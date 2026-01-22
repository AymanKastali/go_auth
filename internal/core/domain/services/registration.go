package services

import (
	"go_auth/internal/core/domain/derr"
	"go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
)

type defaultUserRegistrationPolicy struct {
	userRepo ports.IUserRepository
	roleRepo ports.IRoleRepository
}

func NewDefaultUserRegistrationPolicy(
	userRepo ports.IUserRepository,
	roleRepo ports.IRoleRepository,
) *defaultUserRegistrationPolicy {
	return &defaultUserRegistrationPolicy{
		userRepo: userRepo,
		roleRepo: roleRepo,
	}
}

func (p *defaultUserRegistrationPolicy) Validate(email valueobjects.Email) error {
	exists, err := p.userRepo.ExistsByEmail(email)
	if err != nil {
		return err
	}
	if exists {
		return derr.NewErrEmailAlreadyUsed(email.String())
	}
	return nil
}

func (p *defaultUserRegistrationPolicy) DefaultRoles() ([]valueobjects.RoleID, error) {
	roleName := "user"
	role, err := p.roleRepo.GetByName(roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, derr.NewErrDefaultRoleMissing(roleName)
	}
	roleID := role.ID()
	return []valueobjects.RoleID{roleID}, nil

}
