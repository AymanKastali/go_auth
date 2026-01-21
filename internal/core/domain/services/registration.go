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
		return derr.ErrEmailAlreadyUsed(email.Value())
	}
	return nil
}

func (p *defaultUserRegistrationPolicy) DefaultRoles() ([]valueobjects.RoleID, error) {
	role, err := p.roleRepo.GetByName("user")
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, derr.ErrMissingDefaultRole("user")
	}
	roleID := role.ID()
	return []valueobjects.RoleID{roleID}, nil

}
