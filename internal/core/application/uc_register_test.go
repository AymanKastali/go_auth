package application

import (
	"context"
	"testing"

	"go_auth/internal/core/domain"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegisterUseCase(t *testing.T) {
	validCmd := RegisterUserCommand{Email: "new@example.com", Password: "Str0ng!Pass"}

	t.Run("happy_path", func(t *testing.T) {
		user := testActiveUser()
		uc := NewRegisterUseCase(
			&stubAppUserRepository{},
			&mockRegistrationService{registerMemberResult: user},
			&mockPasswordManager{validateHashResult: testHashedPassword()},
			&stubAppIDGenerator{userID: testUserID()},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		resp, err := uc.Execute(unauthenticatedCtx(), validCmd)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.UserID)
		assert.NotEmpty(t, resp.Email)
	})

	t.Run("invalid_email", func(t *testing.T) {
		uc := NewRegisterUseCase(
			&stubAppUserRepository{},
			&mockRegistrationService{},
			&mockPasswordManager{},
			&stubAppIDGenerator{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		_, err := uc.Execute(context.Background(), RegisterUserCommand{Email: "bad", Password: "Str0ng!Pass"})
		assert.ErrorIs(t, err, domain.ErrUserEmailInvalid)
	})

	t.Run("empty_password", func(t *testing.T) {
		uc := NewRegisterUseCase(
			&stubAppUserRepository{},
			&mockRegistrationService{},
			&mockPasswordManager{},
			&stubAppIDGenerator{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		_, err := uc.Execute(context.Background(), RegisterUserCommand{Email: "a@b.com", Password: ""})
		assert.ErrorIs(t, err, domain.ErrUserPasswordRequired)
	})

	t.Run("policy_violation", func(t *testing.T) {
		uc := NewRegisterUseCase(
			&stubAppUserRepository{},
			&mockRegistrationService{},
			&mockPasswordManager{validateHashErr: domain.ErrPasswordTooShort},
			&stubAppIDGenerator{userID: testUserID()},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		_, err := uc.Execute(context.Background(), validCmd)
		assert.ErrorIs(t, err, domain.ErrPasswordTooShort)
	})

	t.Run("id_gen_fails", func(t *testing.T) {
		uc := NewRegisterUseCase(
			&stubAppUserRepository{},
			&mockRegistrationService{},
			&mockPasswordManager{validateHashResult: testHashedPassword()},
			&stubAppIDGenerator{userIDErr: errTest},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		_, err := uc.Execute(context.Background(), validCmd)
		assert.ErrorIs(t, err, errTest)
	})

	t.Run("email_taken", func(t *testing.T) {
		uc := NewRegisterUseCase(
			&stubAppUserRepository{},
			&mockRegistrationService{registerMemberErr: domain.ErrUserEmailTaken},
			&mockPasswordManager{validateHashResult: testHashedPassword()},
			&stubAppIDGenerator{userID: testUserID()},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		_, err := uc.Execute(context.Background(), validCmd)
		assert.ErrorIs(t, err, domain.ErrUserEmailTaken)
	})

	t.Run("save_fails", func(t *testing.T) {
		user := testActiveUser()
		uc := NewRegisterUseCase(
			&stubAppUserRepository{saveErr: errTest},
			&mockRegistrationService{registerMemberResult: user},
			&mockPasswordManager{validateHashResult: testHashedPassword()},
			&stubAppIDGenerator{userID: testUserID()},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		_, err := uc.Execute(context.Background(), validCmd)
		assert.ErrorIs(t, err, errTest)
	})
}
