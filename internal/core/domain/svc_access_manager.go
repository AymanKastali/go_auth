package domain

import (
	"context"
)

type IAccessManager interface {
	GrantImmediateAccess(
		user *User,
		sid SessionID,
		now Timepoint,
	) (AccessToken, Timepoint, error)
	VerifyAccess(
		ctx context.Context,
		token AccessToken,
		now Timepoint,
	) (*User, SessionID, error)
}

type accessManager struct {
	userRepo     IUserRepository
	accessSvc    IAccessService
	accessPolicy IAccessPolicy
}

func NewAccessManager(
	userRepo IUserRepository,
	accessSvc IAccessService,
	accessPolicy IAccessPolicy,
) IAccessManager {
	return &accessManager{
		userRepo:     userRepo,
		accessSvc:    accessSvc,
		accessPolicy: accessPolicy,
	}
}

func (m *accessManager) GrantImmediateAccess(
	user *User,
	sid SessionID,
	now Timepoint,
) (AccessToken, Timepoint, error) {
	issuedAt := now
	notBefore := now

	ttl := m.accessPolicy.GetAccessLifetime()
	expiresAt := issuedAt.Add(ttl)

	return m.accessSvc.Issue(
		user.ID(),
		user.Email(),
		sid,
		user.Roles(),
		issuedAt,
		expiresAt,
		notBefore,
	)
}

func (m *accessManager) VerifyAccess(ctx context.Context, token AccessToken, now Timepoint) (*User, SessionID, error) {
	// 1. Technical Domain Step: Cryptographic validation (The "Dumb" Service)
	identity, err := m.accessSvc.Validate(token)
	if err != nil {
		return nil, ZeroSessionID, err
	}

	// 2. Identity Resolution: Fetch the Aggregate Root
	user, err := m.userRepo.FindByID(ctx, identity.UserID())
	if err != nil || user == nil {
		return nil, ZeroSessionID, ErrUserNotFound
	}

	// 3. Aggregate Invariant Check: Session Integrity
	// This is where the User Aggregate checks if the SID is revoked or expired
	sid := identity.SessionID()
	if err := user.ValidateIntegrity(sid, now); err != nil {
		return nil, ZeroSessionID, err
	}

	return user, sid, nil
}
