package domain

import (
	"context"
	"time"
)

type IAccessManager interface {
	GrantImmediateAccess(
		ctx context.Context,
		user *User,
		sid SessionID,
		now time.Time,
	) (AccessToken, time.Time, error)
	VerifyAccess(
		ctx context.Context,
		token AccessToken,
		now time.Time,
	) (*User, *Session, error)
	ResolvePermissions(ctx context.Context, roles []RoleName) ([]Permission, error)
}

type accessManager struct {
	userRepo     IUserRepository
	sessionRepo  ISessionRepository
	roleRepo     IRoleRepository
	accessSvc    IAccessService
	accessPolicy IAccessPolicy
}

func NewAccessManager(
	userRepo IUserRepository,
	sessionRepo ISessionRepository,
	roleRepo IRoleRepository,
	accessSvc IAccessService,
	accessPolicy IAccessPolicy,
) IAccessManager {
	return &accessManager{
		userRepo:     userRepo,
		sessionRepo:  sessionRepo,
		roleRepo:     roleRepo,
		accessSvc:    accessSvc,
		accessPolicy: accessPolicy,
	}
}

func (m *accessManager) GrantImmediateAccess(
	ctx context.Context,
	user *User,
	sid SessionID,
	now time.Time,
) (AccessToken, time.Time, error) {
	issuedAt := now
	notBefore := now

	ttl := m.accessPolicy.GetAccessLifetime()
	expiresAt := issuedAt.Add(ttl)

	permissions, err := m.ResolvePermissions(ctx, user.Roles())
	if err != nil {
		return ZeroAccessToken, time.Time{}, err
	}

	return m.accessSvc.Issue(
		user.ID(),
		user.Email(),
		sid,
		user.Roles(),
		permissions,
		issuedAt,
		expiresAt,
		notBefore,
	)
}

func (m *accessManager) VerifyAccess(ctx context.Context, token AccessToken, now time.Time) (*User, *Session, error) {
	// 1. Cryptographic validation
	identity, err := m.accessSvc.Validate(token)
	if err != nil {
		return nil, nil, err
	}

	// 2. Fetch the User aggregate
	user, err := m.userRepo.FindByID(ctx, identity.UserID())
	if err != nil || user == nil {
		return nil, nil, ErrUserNotFound
	}

	if user.IsDeleted() || !user.IsActive() {
		return nil, nil, ErrUserInactive
	}

	// 3. Session integrity check via SessionRepository
	session, err := m.sessionRepo.FindByID(ctx, identity.SessionID())
	if err != nil || session == nil {
		return nil, nil, ErrSessionNotFound
	}

	if !session.IsValid(now) {
		return nil, nil, ErrSessionExpired
	}

	return user, session, nil
}

func (m *accessManager) ResolvePermissions(ctx context.Context, roles []RoleName) ([]Permission, error) {
	seen := make(map[string]struct{})
	var permissions []Permission

	for _, roleName := range roles {
		role, err := m.roleRepo.FindByName(ctx, roleName)
		if err != nil {
			return nil, err
		}
		if role == nil {
			continue
		}
		for _, p := range role.Permissions() {
			key := p.String()
			if _, exists := seen[key]; !exists {
				seen[key] = struct{}{}
				permissions = append(permissions, p)
			}
		}
	}

	return permissions, nil
}
