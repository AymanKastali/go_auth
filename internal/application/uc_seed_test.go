package application

import (
	"context"
	"testing"

	"go_auth/internal/domain"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSeedSuperAdminUseCase(t *testing.T) {
	validCmd := RegisterUserCommand{Email: "admin@example.com", Password: "Str0ng!Pass"}

	t.Run("happy_path", func(t *testing.T) {
		user := testActiveUser()
		uc := NewSeedSuperAdminUseCase(
			&stubAppUserRepository{},
			&mockRegistrationService{registerAdminResult: user},
			&mockPasswordManager{validateHashResult: testHashedPassword()},
			&stubAppIDGenerator{userID: testUserID()},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := uc.Execute(context.Background(), validCmd)
		require.NoError(t, err)
	})

	t.Run("invalid_email", func(t *testing.T) {
		uc := NewSeedSuperAdminUseCase(
			&stubAppUserRepository{},
			&mockRegistrationService{},
			&mockPasswordManager{},
			&stubAppIDGenerator{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := uc.Execute(context.Background(), RegisterUserCommand{Email: "bad", Password: "Str0ng!Pass"})
		assert.ErrorIs(t, err, domain.ErrUserEmailInvalid)
	})

	t.Run("empty_password", func(t *testing.T) {
		uc := NewSeedSuperAdminUseCase(
			&stubAppUserRepository{},
			&mockRegistrationService{},
			&mockPasswordManager{},
			&stubAppIDGenerator{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := uc.Execute(context.Background(), RegisterUserCommand{Email: "a@b.com", Password: ""})
		assert.ErrorIs(t, err, domain.ErrUserPasswordRequired)
	})

	t.Run("policy_violation", func(t *testing.T) {
		uc := NewSeedSuperAdminUseCase(
			&stubAppUserRepository{},
			&mockRegistrationService{},
			&mockPasswordManager{validateHashErr: domain.ErrPasswordTooShort},
			&stubAppIDGenerator{userID: testUserID()},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := uc.Execute(context.Background(), validCmd)
		assert.ErrorIs(t, err, domain.ErrPasswordTooShort)
	})

	t.Run("id_gen_fails", func(t *testing.T) {
		uc := NewSeedSuperAdminUseCase(
			&stubAppUserRepository{},
			&mockRegistrationService{},
			&mockPasswordManager{validateHashResult: testHashedPassword()},
			&stubAppIDGenerator{userIDErr: errTest},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := uc.Execute(context.Background(), validCmd)
		assert.ErrorIs(t, err, errTest)
	})

	t.Run("domain_fails", func(t *testing.T) {
		uc := NewSeedSuperAdminUseCase(
			&stubAppUserRepository{},
			&mockRegistrationService{registerAdminErr: domain.ErrUserEmailTaken},
			&mockPasswordManager{validateHashResult: testHashedPassword()},
			&stubAppIDGenerator{userID: testUserID()},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := uc.Execute(context.Background(), validCmd)
		assert.ErrorIs(t, err, domain.ErrUserEmailTaken)
	})

	t.Run("save_fails", func(t *testing.T) {
		user := testActiveUser()
		uc := NewSeedSuperAdminUseCase(
			&stubAppUserRepository{saveErr: errTest},
			&mockRegistrationService{registerAdminResult: user},
			&mockPasswordManager{validateHashResult: testHashedPassword()},
			&stubAppIDGenerator{userID: testUserID()},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := uc.Execute(context.Background(), validCmd)
		assert.ErrorIs(t, err, errTest)
	})
}
