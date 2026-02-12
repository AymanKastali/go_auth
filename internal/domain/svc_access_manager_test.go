package domain

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccessManager_GrantImmediateAccess(t *testing.T) {
	ctx := context.Background()
	user := newActiveUser()
	sid := validSessionID()

	t.Run("happy_path", func(t *testing.T) {
		at, _ := NewAccessToken("access-tok")
		mgr := NewAccessManager(
			&stubUserRepository{},
			&stubSessionRepository{},
			&stubRoleRepository{},
			&stubAccessService{issueToken: at, issueExpiry: testFuture},
			NewAccessPolicy(AccessPolicyConfig{Lifetime: 15 * time.Minute}),
		)

		tok, exp, err := mgr.GrantImmediateAccess(ctx, user, sid, testNow)
		require.NoError(t, err)
		assert.Equal(t, "access-tok", tok.String())
		assert.True(t, exp.Equal(testFuture))
	})

	t.Run("issue_fails", func(t *testing.T) {
		mgr := NewAccessManager(
			&stubUserRepository{},
			&stubSessionRepository{},
			&stubRoleRepository{},
			&stubAccessService{issueErr: errors.New("jwt error")},
			NewAccessPolicy(AccessPolicyConfig{Lifetime: 15 * time.Minute}),
		)

		_, _, err := mgr.GrantImmediateAccess(ctx, user, sid, testNow)
		assert.Error(t, err)
	})

	t.Run("ttl_calculation_correct", func(t *testing.T) {
		lifetime := 30 * time.Minute

		accessSvc := &captureAccessService{}
		mgr := NewAccessManager(
			&stubUserRepository{},
			&stubSessionRepository{},
			&stubRoleRepository{},
			accessSvc,
			NewAccessPolicy(AccessPolicyConfig{Lifetime: lifetime}),
		)

		_, _, _ = mgr.GrantImmediateAccess(ctx, user, sid, testNow)
		capturedIssuedAt := accessSvc.capturedIssuedAt
		capturedExpiresAt := accessSvc.capturedExpiresAt
		expectedExpiry := testNow.Add(lifetime)
		assert.True(t, capturedIssuedAt.Equal(testNow))
		assert.True(t, capturedExpiresAt.Equal(expectedExpiry))
	})

	t.Run("role_repo_fails", func(t *testing.T) {
		mgr := NewAccessManager(
			&stubUserRepository{},
			&stubSessionRepository{},
			&stubRoleRepository{findByNameErr: errors.New("db error")},
			&stubAccessService{},
			NewAccessPolicy(AccessPolicyConfig{Lifetime: 15 * time.Minute}),
		)

		_, _, err := mgr.GrantImmediateAccess(ctx, user, sid, testNow)
		assert.Error(t, err)
	})

	t.Run("permissions_resolved_from_roles", func(t *testing.T) {
		memberRole := ReconstituteRoleAggregate(
			ReconstituteRoleID("role-001"),
			ReconstituteRoleName("member"),
			"Standard member",
			[]Permission{ReconstitutePermission("users", "read_self"), ReconstitutePermission("content", "read")},
		)
		accessSvc := &captureAccessService{}
		mgr := NewAccessManager(
			&stubUserRepository{},
			&stubSessionRepository{},
			&stubRoleRepository{findByNameResult: memberRole},
			accessSvc,
			NewAccessPolicy(AccessPolicyConfig{Lifetime: 15 * time.Minute}),
		)

		_, _, _ = mgr.GrantImmediateAccess(ctx, user, sid, testNow)
		assert.Len(t, accessSvc.capturedPermissions, 2)
		assert.Equal(t, "users:read_self", accessSvc.capturedPermissions[0].String())
		assert.Equal(t, "content:read", accessSvc.capturedPermissions[1].String())
	})
}

// captureAccessService records arguments passed to Issue for inspection.
type captureAccessService struct {
	capturedIssuedAt    time.Time
	capturedExpiresAt   time.Time
	capturedPermissions []Permission
}

func (s *captureAccessService) Issue(_ UserID, _ Email, _ SessionID, _ []RoleName, permissions []Permission, issuedAt, expiresAt, _ time.Time) (AccessToken, time.Time, error) {
	s.capturedIssuedAt = issuedAt
	s.capturedExpiresAt = expiresAt
	s.capturedPermissions = permissions
	at, _ := NewAccessToken("tok")
	return at, expiresAt, nil
}

func (s *captureAccessService) Validate(_ AccessToken) (AccessIdentity, error) {
	return ZeroAccessIdentity, nil
}

func TestAccessManager_VerifyAccess(t *testing.T) {
	ctx := context.Background()

	t.Run("happy_path", func(t *testing.T) {
		user := newActiveUser()
		session := newActiveSession()
		ai, _ := NewAccessIdentity(validUserID(), validSessionID(), validEmail(), []RoleName{ReconstituteRoleName("member")}, nil)
		mgr := NewAccessManager(
			&stubUserRepository{findByIDResult: user},
			&stubSessionRepository{findByIDResult: session},
			&stubRoleRepository{},
			&stubAccessService{validateID: ai},
			NewAccessPolicy(AccessPolicyConfig{Lifetime: 15 * time.Minute}),
		)

		at, _ := NewAccessToken("tok")
		u, sess, err := mgr.VerifyAccess(ctx, at, testNow)
		require.NoError(t, err)
		assert.Equal(t, validUserID(), u.ID())
		assert.Equal(t, validSessionID(), sess.ID())
	})

	t.Run("token_invalid", func(t *testing.T) {
		mgr := NewAccessManager(
			&stubUserRepository{},
			&stubSessionRepository{},
			&stubRoleRepository{},
			&stubAccessService{validateErr: ErrTokenInvalid},
			NewAccessPolicy(AccessPolicyConfig{Lifetime: 15 * time.Minute}),
		)

		at, _ := NewAccessToken("bad")
		_, _, err := mgr.VerifyAccess(ctx, at, testNow)
		assert.ErrorIs(t, err, ErrTokenInvalid)
	})

	t.Run("user_not_found", func(t *testing.T) {
		ai, _ := NewAccessIdentity(validUserID(), validSessionID(), validEmail(), []RoleName{ReconstituteRoleName("member")}, nil)
		mgr := NewAccessManager(
			&stubUserRepository{findByIDResult: nil},
			&stubSessionRepository{},
			&stubRoleRepository{},
			&stubAccessService{validateID: ai},
			NewAccessPolicy(AccessPolicyConfig{Lifetime: 15 * time.Minute}),
		)

		at, _ := NewAccessToken("tok")
		_, _, err := mgr.VerifyAccess(ctx, at, testNow)
		assert.ErrorIs(t, err, ErrUserNotFound)
	})

	t.Run("session_not_found", func(t *testing.T) {
		user := newActiveUser()
		ai, _ := NewAccessIdentity(validUserID(), validSessionID(), validEmail(), []RoleName{ReconstituteRoleName("member")}, nil)
		mgr := NewAccessManager(
			&stubUserRepository{findByIDResult: user},
			&stubSessionRepository{findByIDResult: nil},
			&stubRoleRepository{},
			&stubAccessService{validateID: ai},
			NewAccessPolicy(AccessPolicyConfig{Lifetime: 15 * time.Minute}),
		)

		at, _ := NewAccessToken("tok")
		_, _, err := mgr.VerifyAccess(ctx, at, testNow)
		assert.ErrorIs(t, err, ErrSessionNotFound)
	})

	t.Run("session_revoked", func(t *testing.T) {
		user := newActiveUser()
		revokedSession := ReconstituteSession(validSessionID(), validUserID(), validHashedToken(), validDeviceIdentity(), testFuture, testNow, true)
		ai, _ := NewAccessIdentity(validUserID(), validSessionID(), validEmail(), []RoleName{ReconstituteRoleName("member")}, nil)
		mgr := NewAccessManager(
			&stubUserRepository{findByIDResult: user},
			&stubSessionRepository{findByIDResult: revokedSession},
			&stubRoleRepository{},
			&stubAccessService{validateID: ai},
			NewAccessPolicy(AccessPolicyConfig{Lifetime: 15 * time.Minute}),
		)

		at, _ := NewAccessToken("tok")
		_, _, err := mgr.VerifyAccess(ctx, at, testNow)
		assert.ErrorIs(t, err, ErrSessionExpired)
	})

	t.Run("session_expired", func(t *testing.T) {
		user := newActiveUser()
		expiredSession := ReconstituteSession(validSessionID(), validUserID(), validHashedToken(), validDeviceIdentity(), testPast, testPast, false)
		ai, _ := NewAccessIdentity(validUserID(), validSessionID(), validEmail(), []RoleName{ReconstituteRoleName("member")}, nil)
		mgr := NewAccessManager(
			&stubUserRepository{findByIDResult: user},
			&stubSessionRepository{findByIDResult: expiredSession},
			&stubRoleRepository{},
			&stubAccessService{validateID: ai},
			NewAccessPolicy(AccessPolicyConfig{Lifetime: 15 * time.Minute}),
		)

		at, _ := NewAccessToken("tok")
		_, _, err := mgr.VerifyAccess(ctx, at, testNow)
		assert.ErrorIs(t, err, ErrSessionExpired)
	})
}

func TestAccessManager_ResolvePermissions(t *testing.T) {
	ctx := context.Background()

	t.Run("happy_path", func(t *testing.T) {
		memberRole := ReconstituteRoleAggregate(
			ReconstituteRoleID("role-001"),
			ReconstituteRoleName("member"),
			"Standard member",
			[]Permission{ReconstitutePermission("users", "read_self"), ReconstitutePermission("content", "read")},
		)
		mgr := NewAccessManager(
			&stubUserRepository{},
			&stubSessionRepository{},
			&stubRoleRepository{findByNameResult: memberRole},
			&stubAccessService{},
			NewAccessPolicy(AccessPolicyConfig{Lifetime: 15 * time.Minute}),
		)

		perms, err := mgr.ResolvePermissions(ctx, []RoleName{ReconstituteRoleName("member")})
		require.NoError(t, err)
		assert.Len(t, perms, 2)
		assert.Equal(t, "users:read_self", perms[0].String())
		assert.Equal(t, "content:read", perms[1].String())
	})

	t.Run("role_repo_error", func(t *testing.T) {
		mgr := NewAccessManager(
			&stubUserRepository{},
			&stubSessionRepository{},
			&stubRoleRepository{findByNameErr: errors.New("db error")},
			&stubAccessService{},
			NewAccessPolicy(AccessPolicyConfig{Lifetime: 15 * time.Minute}),
		)

		_, err := mgr.ResolvePermissions(ctx, []RoleName{ReconstituteRoleName("member")})
		assert.Error(t, err)
	})
}
