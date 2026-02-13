package domain

import (
	"context"
	"time"
)

type IRegisterAdmin interface {
	Register(
		ctx context.Context,
		id UserID,
		email Email,
		pwd HashedPassword,
		now time.Time,
	) (*User, error)
}

type registerAdmin struct {
	userRepo       IUserRepository
	roleProvider   IRegistrationRoleProvider
	registerPolicy IRegisterPolicy
}

func NewRegisterAdmin(
	userRepo IUserRepository,
	roleProvider IRegistrationRoleProvider,
	registerPolicy IRegisterPolicy,
) IRegisterAdmin {
	return &registerAdmin{
		userRepo:       userRepo,
		roleProvider:   roleProvider,
		registerPolicy: registerPolicy,
	}
}

func (r *registerAdmin) Register(
	ctx context.Context,
	id UserID,
	email Email,
	pwd HashedPassword,
	now time.Time,
) (*User, error) {
	user, err := registerUser(ctx, r.userRepo, r.registerPolicy, id, email, pwd, now)
	if err != nil {
		return nil, err
	}

	roleName, err := r.roleProvider.DefaultAdminRole(ctx)
	if err != nil {
		return nil, err
	}
	if err := user.AssignRole(roleName, now); err != nil {
		return nil, err
	}

	return user, nil
}
