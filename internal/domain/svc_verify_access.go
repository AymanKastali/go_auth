package domain

import (
	"context"
	"time"
)

type IVerifyAccess interface {
	Verify(ctx context.Context, token AccessToken, now time.Time) (*User, *Session, error)
}

type verifyAccess struct {
	userRepo    IUserRepository
	sessionRepo ISessionRepository
	accessSvc   IAccessService
}

func NewVerifyAccess(
	userRepo IUserRepository,
	sessionRepo ISessionRepository,
	accessSvc IAccessService,
) IVerifyAccess {
	return &verifyAccess{
		userRepo:    userRepo,
		sessionRepo: sessionRepo,
		accessSvc:   accessSvc,
	}
}

func (v *verifyAccess) Verify(ctx context.Context, token AccessToken, now time.Time) (*User, *Session, error) {
	identity, err := v.accessSvc.Validate(token)
	if err != nil {
		return nil, nil, err
	}

	user, err := v.userRepo.FindByID(ctx, identity.UserID())
	if err != nil || user == nil {
		return nil, nil, ErrUserNotFound
	}

	if user.IsDeleted() || !user.IsActive() {
		return nil, nil, ErrUserInactive
	}

	session, err := v.sessionRepo.FindByID(ctx, identity.SessionID())
	if err != nil || session == nil {
		return nil, nil, ErrSessionNotFound
	}

	if !session.IsValid(now) {
		return nil, nil, ErrSessionExpired
	}

	return user, session, nil
}
