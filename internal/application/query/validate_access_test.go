package query

import (
	"testing"

	"go_auth/internal/domain"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateAccessHandler(t *testing.T) {
	validAI := func() domain.AccessIdentity {
		ai, _ := domain.NewAccessIdentity(testUserID(), testSessionID(), domain.ReconstituteEmail("test@example.com"), []domain.RoleName{domain.ReconstituteRoleName("member")}, nil)
		return ai
	}

	t.Run("happy_path", func(t *testing.T) {
		user := testActiveUser()
		session := testActiveSession()
		h := NewValidateAccessHandler(
			&mockAccessService{validateID: validAI()},
			&stubAppUserRepository{findByIDResult: user},
			&stubAppSessionRepository{findByIDResult: session},
			&stubAppRoleRepository{},
			&mockResolvePermissions{},
			&stubClock{now: appTestNow},
		)

		resp, err := h.Handle(unauthenticatedCtx(), ValidateAccessQuery{AccessToken: "tok"})
		require.NoError(t, err)
		assert.Equal(t, "user-001", resp.UserID)
		assert.Equal(t, "sess-001", resp.SessionID)
		assert.Contains(t, resp.Roles, "member")
		assert.Empty(t, resp.Permissions)
	})

	t.Run("with_permissions", func(t *testing.T) {
		user := testActiveUser()
		session := testActiveSession()
		h := NewValidateAccessHandler(
			&mockAccessService{validateID: validAI()},
			&stubAppUserRepository{findByIDResult: user},
			&stubAppSessionRepository{findByIDResult: session},
			&stubAppRoleRepository{},
			&mockResolvePermissions{
				resolveResult: []domain.Permission{
					domain.ReconstitutePermission("users", "read_self"),
					domain.ReconstitutePermission("content", "read"),
				},
			},
			&stubClock{now: appTestNow},
		)

		resp, err := h.Handle(unauthenticatedCtx(), ValidateAccessQuery{
			AccessToken:        "tok",
			IncludePermissions: true,
		})
		require.NoError(t, err)
		assert.Equal(t, "user-001", resp.UserID)
		assert.Equal(t, "sess-001", resp.SessionID)
		assert.Equal(t, []string{"users:read_self", "content:read"}, resp.Permissions)
	})

	t.Run("without_permissions", func(t *testing.T) {
		user := testActiveUser()
		session := testActiveSession()
		h := NewValidateAccessHandler(
			&mockAccessService{validateID: validAI()},
			&stubAppUserRepository{findByIDResult: user},
			&stubAppSessionRepository{findByIDResult: session},
			&stubAppRoleRepository{},
			&mockResolvePermissions{},
			&stubClock{now: appTestNow},
		)

		resp, err := h.Handle(unauthenticatedCtx(), ValidateAccessQuery{
			AccessToken:        "tok",
			IncludePermissions: false,
		})
		require.NoError(t, err)
		assert.Nil(t, resp.Permissions)
	})

	t.Run("empty_token", func(t *testing.T) {
		h := NewValidateAccessHandler(
			&mockAccessService{},
			&stubAppUserRepository{},
			&stubAppSessionRepository{},
			&stubAppRoleRepository{},
			&mockResolvePermissions{},
			&stubClock{now: appTestNow},
		)

		_, err := h.Handle(unauthenticatedCtx(), ValidateAccessQuery{AccessToken: ""})
		assert.ErrorIs(t, err, domain.ErrTokenInvalid)
	})

	t.Run("token_validation_fails", func(t *testing.T) {
		h := NewValidateAccessHandler(
			&mockAccessService{validateErr: domain.ErrTokenInvalid},
			&stubAppUserRepository{},
			&stubAppSessionRepository{},
			&stubAppRoleRepository{},
			&mockResolvePermissions{},
			&stubClock{now: appTestNow},
		)

		_, err := h.Handle(unauthenticatedCtx(), ValidateAccessQuery{AccessToken: "bad"})
		assert.ErrorIs(t, err, domain.ErrTokenInvalid)
	})

	t.Run("user_not_found", func(t *testing.T) {
		h := NewValidateAccessHandler(
			&mockAccessService{validateID: validAI()},
			&stubAppUserRepository{findByIDResult: nil},
			&stubAppSessionRepository{},
			&stubAppRoleRepository{},
			&mockResolvePermissions{},
			&stubClock{now: appTestNow},
		)

		_, err := h.Handle(unauthenticatedCtx(), ValidateAccessQuery{AccessToken: "tok"})
		assert.ErrorIs(t, err, domain.ErrUserNotFound)
	})

	t.Run("session_not_found", func(t *testing.T) {
		user := testActiveUser()
		h := NewValidateAccessHandler(
			&mockAccessService{validateID: validAI()},
			&stubAppUserRepository{findByIDResult: user},
			&stubAppSessionRepository{findByIDResult: nil},
			&stubAppRoleRepository{},
			&mockResolvePermissions{},
			&stubClock{now: appTestNow},
		)

		_, err := h.Handle(unauthenticatedCtx(), ValidateAccessQuery{AccessToken: "tok"})
		assert.ErrorIs(t, err, domain.ErrSessionNotFound)
	})

	t.Run("session_expired", func(t *testing.T) {
		user := testActiveUser()
		expiredSession := domain.ReconstituteSession(testSessionID(), testUserID(), domain.ReconstituteHashedToken("hashed-tok"), domain.ZeroHashedToken, testDeviceIdentity(), appTestNow.Add(-1), appTestNow.Add(-2), false)
		h := NewValidateAccessHandler(
			&mockAccessService{validateID: validAI()},
			&stubAppUserRepository{findByIDResult: user},
			&stubAppSessionRepository{findByIDResult: expiredSession},
			&stubAppRoleRepository{},
			&mockResolvePermissions{},
			&stubClock{now: appTestNow},
		)

		_, err := h.Handle(unauthenticatedCtx(), ValidateAccessQuery{AccessToken: "tok"})
		assert.ErrorIs(t, err, domain.ErrSessionExpired)
	})
}
