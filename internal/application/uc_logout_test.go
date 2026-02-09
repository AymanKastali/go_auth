package application

import (
	"testing"

	"go_auth/internal/domain"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogoutUseCase(t *testing.T) {
	validCmd := LogoutCommand{UserID: "user-001", SessionID: "sess-001"}

	t.Run("happy_path", func(t *testing.T) {
		session := testActiveSession()
		uc := NewLogoutUseCase(
			&stubAppSessionRepository{findByIDResult: session},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := uc.Execute(unauthenticatedCtx(), validCmd)
		require.NoError(t, err)
	})

	t.Run("empty_userID", func(t *testing.T) {
		uc := NewLogoutUseCase(
			&stubAppSessionRepository{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := uc.Execute(unauthenticatedCtx(), LogoutCommand{UserID: "", SessionID: "sess"})
		assert.ErrorIs(t, err, domain.ErrUserIDRequired)
	})

	t.Run("empty_sessionID", func(t *testing.T) {
		uc := NewLogoutUseCase(
			&stubAppSessionRepository{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := uc.Execute(unauthenticatedCtx(), LogoutCommand{UserID: "user-001", SessionID: ""})
		assert.ErrorIs(t, err, domain.ErrSessionIDRequired)
	})

	t.Run("session_not_found", func(t *testing.T) {
		uc := NewLogoutUseCase(
			&stubAppSessionRepository{findByIDResult: nil},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := uc.Execute(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, domain.ErrSessionNotFound)
	})

	t.Run("already_revoked", func(t *testing.T) {
		revokedSession := domain.ReconstituteSession(
			testSessionID(), testUserID(),
			domain.ReconstituteHashedToken("hashed-tok"),
			testDeviceIdentity(), appTestFuture, appTestNow, true,
		)
		uc := NewLogoutUseCase(
			&stubAppSessionRepository{findByIDResult: revokedSession},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := uc.Execute(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, domain.ErrSessionAlreadyRevoked)
	})

	t.Run("save_fails", func(t *testing.T) {
		session := testActiveSession()
		uc := NewLogoutUseCase(
			&stubAppSessionRepository{findByIDResult: session, saveErr: errTest},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := uc.Execute(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, errTest)
	})
}
