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
	userRepo       IUserRepository
	registerPolicy IRegisterPolicy
}

func NewRegistrationService(
	userRepo IUserRepository,
	registerPolicy IRegisterPolicy,
) *registrationService {
	return &registrationService{
		userRepo:       userRepo,
		registerPolicy: registerPolicy,
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

	if err := user.AssignRole(RoleMember, now); err != nil {
		return nil, err
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

	if err := user.AssignRole(RoleAdmin, now); err != nil {
		return nil, err
	}

	return user, nil
}
