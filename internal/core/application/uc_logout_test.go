package application

import (
	"testing"

	"go_auth/internal/core/domain"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogoutUseCase(t *testing.T) {
	validCmd := LogoutCommand{UserID: "user-001", SessionID: "sess-001"}

	t.Run("happy_path", func(t *testing.T) {
		user := testActiveUser()
		uc := NewLogoutUseCase(
			&stubAppUserRepository{findByIDResult: user},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := uc.Execute(unauthenticatedCtx(), validCmd)
		require.NoError(t, err)
	})

	t.Run("empty_userID", func(t *testing.T) {
		uc := NewLogoutUseCase(
			&stubAppUserRepository{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := uc.Execute(unauthenticatedCtx(), LogoutCommand{UserID: "", SessionID: "sess"})
		assert.ErrorIs(t, err, domain.ErrUserIDRequired)
	})

	t.Run("empty_sessionID", func(t *testing.T) {
		uc := NewLogoutUseCase(
			&stubAppUserRepository{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := uc.Execute(unauthenticatedCtx(), LogoutCommand{UserID: "user-001", SessionID: ""})
		assert.ErrorIs(t, err, domain.ErrSessionIDRequired)
	})

	t.Run("user_not_found", func(t *testing.T) {
		uc := NewLogoutUseCase(
			&stubAppUserRepository{findByIDResult: nil},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := uc.Execute(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, domain.ErrUserNotFound)
	})

	t.Run("already_revoked", func(t *testing.T) {
		user := testActiveUser()
		uc := NewLogoutUseCase(
			&stubAppUserRepository{findByIDResult: user},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)
		// First revoke succeeds
		_ = uc.Execute(unauthenticatedCtx(), validCmd)
		// Second should fail
		err := uc.Execute(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, domain.ErrSessionAlreadyRevoked)
	})

	t.Run("save_fails", func(t *testing.T) {
		user := testActiveUser()
		uc := NewLogoutUseCase(
			&stubAppUserRepository{findByIDResult: user, saveErr: errTest},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := uc.Execute(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, errTest)
	})
}
