package domain

import (
	"context"
)

type IAccessManager interface {
	GrantImmediateAccess(
		ctx context.Context,
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
	now Timepoint,
) (AccessToken, Timepoint, error) {
	issuedAt := now
	notBefore := now

	ttl := m.accessPolicy.GetAccessLifetime()
	expiresAt := issuedAt.Add(ttl)

	permissions, err := m.resolvePermissions(ctx, user.Roles())
	if err != nil {
		return ZeroAccessToken, ZeroTimepoint, err
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

func (m *accessManager) VerifyAccess(ctx context.Context, token AccessToken, now Timepoint) (*User, SessionID, error) {
	// 1. Cryptographic validation
	identity, err := m.accessSvc.Validate(token)
	if err != nil {
		return nil, ZeroSessionID, err
	}

	// 2. Fetch the User aggregate
	user, err := m.userRepo.FindByID(ctx, identity.UserID())
	if err != nil || user == nil {
		return nil, ZeroSessionID, ErrUserNotFound
	}

	if user.IsDeleted() || !user.IsActive() {
		return nil, ZeroSessionID, ErrUserInactive
	}

	// 3. Session integrity check via SessionRepository
	sid := identity.SessionID()
	session, err := m.sessionRepo.FindByID(ctx, sid)
	if err != nil || session == nil {
		return nil, ZeroSessionID, ErrSessionNotFound
	}

	if !session.IsValid(now) {
		return nil, ZeroSessionID, ErrSessionExpired
	}

	return user, sid, nil
}

func (m *accessManager) resolvePermissions(ctx context.Context, roles []RoleName) ([]Permission, error) {
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
