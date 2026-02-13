package query

import (
	"testing"

	"go_auth/internal/domain"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateAccessHandler(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		user := testActiveUser()
		session := testActiveSession()
		h := NewValidateAccessHandler(
			&mockVerifyAccess{verifyUser: user, verifySess: session},
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
			&mockVerifyAccess{verifyUser: user, verifySess: session},
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
			&mockVerifyAccess{verifyUser: user, verifySess: session},
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
			&mockVerifyAccess{},
			&mockResolvePermissions{},
			&stubClock{now: appTestNow},
		)

		_, err := h.Handle(unauthenticatedCtx(), ValidateAccessQuery{AccessToken: ""})
		assert.ErrorIs(t, err, domain.ErrTokenInvalid)
	})

	t.Run("verification_fails", func(t *testing.T) {
		h := NewValidateAccessHandler(
			&mockVerifyAccess{verifyErr: domain.ErrTokenInvalid},
			&mockResolvePermissions{},
			&stubClock{now: appTestNow},
		)

		_, err := h.Handle(unauthenticatedCtx(), ValidateAccessQuery{AccessToken: "bad"})
		assert.ErrorIs(t, err, domain.ErrTokenInvalid)
	})
}
