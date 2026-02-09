package application

import (
	"testing"

	"go_auth/internal/domain"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpdateMeUseCase(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		user := testActiveUser()
		uc := NewUpdateMeUseCase(
			&stubAppUserRepository{findByIDResult: user, findByEmailResult: nil},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := uc.Execute(authenticatedCtx("user-001", "sess-001"), UpdateMeCommand{Email: "new@example.com"})
		require.NoError(t, err)
	})

	t.Run("unauthenticated", func(t *testing.T) {
		uc := NewUpdateMeUseCase(
			&stubAppUserRepository{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := uc.Execute(unauthenticatedCtx(), UpdateMeCommand{Email: "a@b.com"})
		assert.ErrorIs(t, err, ErrUnauthorized)
	})

	t.Run("invalid_email", func(t *testing.T) {
		uc := NewUpdateMeUseCase(
			&stubAppUserRepository{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := uc.Execute(authenticatedCtx("user-001", "sess-001"), UpdateMeCommand{Email: "bad"})
		assert.ErrorIs(t, err, domain.ErrUserEmailInvalid)
	})

	t.Run("user_not_found", func(t *testing.T) {
		uc := NewUpdateMeUseCase(
			&stubAppUserRepository{findByIDResult: nil},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := uc.Execute(authenticatedCtx("user-001", "sess-001"), UpdateMeCommand{Email: "a@b.com"})
		assert.ErrorIs(t, err, ErrResourceNotFound)
	})

	t.Run("email_taken", func(t *testing.T) {
		user := testActiveUser()
		existingUser := testActiveUser()
		uc := NewUpdateMeUseCase(
			&stubAppUserRepository{findByIDResult: user, findByEmailResult: existingUser},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := uc.Execute(authenticatedCtx("user-001", "sess-001"), UpdateMeCommand{Email: "taken@example.com"})
		assert.ErrorIs(t, err, domain.ErrUserEmailTaken)
	})

	t.Run("same_email_idempotent", func(t *testing.T) {
		user := testActiveUser()
		uc := NewUpdateMeUseCase(
			&stubAppUserRepository{findByIDResult: user},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := uc.Execute(authenticatedCtx("user-001", "sess-001"), UpdateMeCommand{Email: "test@example.com"})
		require.NoError(t, err)
	})

	t.Run("save_fails", func(t *testing.T) {
		user := testActiveUser()
		uc := NewUpdateMeUseCase(
			&stubAppUserRepository{findByIDResult: user, findByEmailResult: nil, saveErr: errTest},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := uc.Execute(authenticatedCtx("user-001", "sess-001"), UpdateMeCommand{Email: "new@example.com"})
		assert.ErrorIs(t, err, errTest)
	})
}
