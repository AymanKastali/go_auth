package command

import (
	"testing"

	"go_auth/internal/application"
	"go_auth/internal/domain"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChangePasswordHandler(t *testing.T) {
	validCmd := ChangePasswordCommand{OldPassword: "OldStr0ng!", NewPassword: "NewStr0ng!"}

	t.Run("happy_path", func(t *testing.T) {
		user := testActiveUser()
		h := NewChangePasswordHandler(
			&stubAppUserRepository{findByIDResult: user},
			&stubAppSessionRepository{},
			&mockAccountManager{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := h.Handle(authenticatedCtx("user-001", "sess-001"), validCmd)
		require.NoError(t, err)
	})

	t.Run("unauthenticated", func(t *testing.T) {
		h := NewChangePasswordHandler(
			&stubAppUserRepository{},
			&stubAppSessionRepository{},
			&mockAccountManager{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := h.Handle(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, application.ErrUnauthorized)
	})

	t.Run("user_not_found", func(t *testing.T) {
		h := NewChangePasswordHandler(
			&stubAppUserRepository{findByIDResult: nil},
			&stubAppSessionRepository{},
			&mockAccountManager{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := h.Handle(authenticatedCtx("user-001", "sess-001"), validCmd)
		assert.ErrorIs(t, err, application.ErrResourceNotFound)
	})

	t.Run("empty_old_password", func(t *testing.T) {
		user := testActiveUser()
		h := NewChangePasswordHandler(
			&stubAppUserRepository{findByIDResult: user},
			&stubAppSessionRepository{},
			&mockAccountManager{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := h.Handle(authenticatedCtx("user-001", "sess-001"), ChangePasswordCommand{OldPassword: "", NewPassword: "New1!"})
		assert.ErrorIs(t, err, domain.ErrUserPasswordRequired)
	})

	t.Run("domain_fails", func(t *testing.T) {
		user := testActiveUser()
		h := NewChangePasswordHandler(
			&stubAppUserRepository{findByIDResult: user},
			&stubAppSessionRepository{},
			&mockAccountManager{changeErr: domain.ErrAuthenticationFailed},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := h.Handle(authenticatedCtx("user-001", "sess-001"), validCmd)
		assert.ErrorIs(t, err, domain.ErrAuthenticationFailed)
	})

	t.Run("save_fails", func(t *testing.T) {
		user := testActiveUser()
		h := NewChangePasswordHandler(
			&stubAppUserRepository{findByIDResult: user, saveErr: errTest},
			&stubAppSessionRepository{},
			&mockAccountManager{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := h.Handle(authenticatedCtx("user-001", "sess-001"), validCmd)
		assert.ErrorIs(t, err, errTest)
	})

	t.Run("session_revoke_fails", func(t *testing.T) {
		user := testActiveUser()
		h := NewChangePasswordHandler(
			&stubAppUserRepository{findByIDResult: user},
			&stubAppSessionRepository{revokeAllErr: errTest},
			&mockAccountManager{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := h.Handle(authenticatedCtx("user-001", "sess-001"), validCmd)
		assert.ErrorIs(t, err, errTest)
	})
}
