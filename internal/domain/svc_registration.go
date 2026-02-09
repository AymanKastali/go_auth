package domain

import (
	"context"
)

type IRegistrationService interface {
	RegisterNewMember(
		ctx context.Context,
		id UserID,
		email Email,
		pwd HashedPassword,
		now Timepoint,
	) (*User, error)
	RegisterNewSuperAdmin(
		ctx context.Context,
		id UserID,
		email Email,
		pwd HashedPassword,
		now Timepoint,
	) (*User, error)
}

type registrationService struct {
	userRepo         IUserRepository
	roleProvider     IRegistrationRoleProvider
	registerPolicy   IRegisterPolicy
	activationPolicy IActivationPolicy
}

func NewRegistrationService(
	userRepo IUserRepository,
	roleProvider IRegistrationRoleProvider,
	registerPolicy IRegisterPolicy,
	activationPolicy IActivationPolicy,
) *registrationService {
	return &registrationService{
		userRepo:         userRepo,
		roleProvider:     roleProvider,
		registerPolicy:   registerPolicy,
		activationPolicy: activationPolicy,
	}
}

func (s *registrationService) RegisterNewMember(
	ctx context.Context,
	id UserID,
	email Email,
	pwd HashedPassword,
	now Timepoint,
) (*User, error) {
	if err := s.registerPolicy.Validate(email); err != nil {
		return nil, err
	}

	existing, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, ErrUserEmailTaken
	}

	user, err := NewUser(id, email, pwd, now)
	if err != nil {
		return nil, err
	}

	roleName, err := s.roleProvider.DefaultMemberRole(ctx)
	if err != nil {
		return nil, err
	}
	if err := user.AssignRole(roleName, now); err != nil {
		return nil, err
	}

	if s.activationPolicy.RequiresEmailActivation() {
		if err := user.Deactivate(now); err != nil {
			return nil, err
		}
	}

	return user, nil
}

func (s *registrationService) RegisterNewSuperAdmin(
	ctx context.Context,
	id UserID,
	email Email,
	pwd HashedPassword,
	now Timepoint,
) (*User, error) {
	if err := s.registerPolicy.Validate(email); err != nil {
		return nil, err
	}

	existing, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, ErrUserEmailTaken
	}

	user, err := NewUser(id, email, pwd, now)
	if err != nil {
		return nil, err
	}

	roleName, err := s.roleProvider.DefaultAdminRole(ctx)
	if err != nil {
		return nil, err
	}
	if err := user.AssignRole(roleName, now); err != nil {
		return nil, err
	}

	return user, nil
}
