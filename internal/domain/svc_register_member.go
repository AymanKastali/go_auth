package domain

import (
	"context"
	"time"
)

type IRegisterMember interface {
	Register(
		ctx context.Context,
		id UserID,
		email Email,
		pwd HashedPassword,
		now time.Time,
	) (*User, error)
}

type registerMember struct {
	userRepo         IUserRepository
	roleProvider     IRegistrationRoleProvider
	registerPolicy   IRegisterPolicy
	activationPolicy IActivationPolicy
}

func NewRegisterMember(
	userRepo IUserRepository,
	roleProvider IRegistrationRoleProvider,
	registerPolicy IRegisterPolicy,
	activationPolicy IActivationPolicy,
) IRegisterMember {
	return &registerMember{
		userRepo:         userRepo,
		roleProvider:     roleProvider,
		registerPolicy:   registerPolicy,
		activationPolicy: activationPolicy,
	}
}

func (r *registerMember) Register(
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

	roleName, err := r.roleProvider.DefaultMemberRole(ctx)
	if err != nil {
		return nil, err
	}
	if err := user.AssignRole(roleName, now); err != nil {
		return nil, err
	}

	if r.activationPolicy.RequiresEmailActivation() {
		if err := user.Deactivate(now); err != nil {
			return nil, err
		}
	}

	return user, nil
}

func registerUser(
	ctx context.Context,
	userRepo IUserRepository,
	registerPolicy IRegisterPolicy,
	id UserID,
	email Email,
	pwd HashedPassword,
	now time.Time,
) (*User, error) {
	if err := registerPolicy.Validate(email); err != nil {
		return nil, err
	}

	existing, err := userRepo.FindByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, ErrUserEmailTaken
	}

	return NewUser(id, email, pwd, now)
}
