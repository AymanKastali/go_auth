package application

import (
	"testing"

	"go_auth/internal/core/domain"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChangePasswordUseCase(t *testing.T) {
	validCmd := ChangePasswordCommand{OldPassword: "OldStr0ng!", NewPassword: "NewStr0ng!"}

	t.Run("happy_path", func(t *testing.T) {
		user := testActiveUser()
		uc := NewChangePasswordUseCase(
			&stubAppUserRepository{findByIDResult: user},
			&stubAppSessionRepository{},
			&mockAccountManager{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := uc.Execute(authenticatedCtx("user-001", "sess-001"), validCmd)
		require.NoError(t, err)
	})

	t.Run("unauthenticated", func(t *testing.T) {
		uc := NewChangePasswordUseCase(
			&stubAppUserRepository{},
			&stubAppSessionRepository{},
			&mockAccountManager{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := uc.Execute(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, ErrUnauthorized)
	})

	t.Run("user_not_found", func(t *testing.T) {
		uc := NewChangePasswordUseCase(
			&stubAppUserRepository{findByIDResult: nil},
			&stubAppSessionRepository{},
			&mockAccountManager{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := uc.Execute(authenticatedCtx("user-001", "sess-001"), validCmd)
		assert.ErrorIs(t, err, ErrResourceNotFound)
	})

	t.Run("empty_old_password", func(t *testing.T) {
		user := testActiveUser()
		uc := NewChangePasswordUseCase(
			&stubAppUserRepository{findByIDResult: user},
			&stubAppSessionRepository{},
			&mockAccountManager{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := uc.Execute(authenticatedCtx("user-001", "sess-001"), ChangePasswordCommand{OldPassword: "", NewPassword: "New1!"})
		assert.ErrorIs(t, err, domain.ErrUserPasswordRequired)
	})

	t.Run("domain_fails", func(t *testing.T) {
		user := testActiveUser()
		uc := NewChangePasswordUseCase(
			&stubAppUserRepository{findByIDResult: user},
			&stubAppSessionRepository{},
			&mockAccountManager{changeErr: domain.ErrAuthenticationFailed},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := uc.Execute(authenticatedCtx("user-001", "sess-001"), validCmd)
		assert.ErrorIs(t, err, domain.ErrAuthenticationFailed)
	})

	t.Run("save_fails", func(t *testing.T) {
		user := testActiveUser()
		uc := NewChangePasswordUseCase(
			&stubAppUserRepository{findByIDResult: user, saveErr: errTest},
			&stubAppSessionRepository{},
			&mockAccountManager{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := uc.Execute(authenticatedCtx("user-001", "sess-001"), validCmd)
		assert.ErrorIs(t, err, errTest)
	})

	t.Run("session_revoke_fails", func(t *testing.T) {
		user := testActiveUser()
		uc := NewChangePasswordUseCase(
			&stubAppUserRepository{findByIDResult: user},
			&stubAppSessionRepository{revokeAllErr: errTest},
			&mockAccountManager{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := uc.Execute(authenticatedCtx("user-001", "sess-001"), validCmd)
		assert.ErrorIs(t, err, errTest)
	})
}
