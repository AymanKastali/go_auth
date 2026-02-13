package command

import (
	"context"
	"testing"

	"go_auth/internal/domain"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSeedSuperAdminHandler(t *testing.T) {
	validCmd := RegisterUserCommand{Email: "admin@example.com", Password: "Str0ng!Pass"}

	validPolicy := &mockPasswordPolicy{
		validateResult: domain.ReconstituteValidatedPassword("Str0ng!Pass"),
	}
	validSvc := &mockPasswordService{hashResult: testHashedPassword()}

	t.Run("happy_path", func(t *testing.T) {
		user := testActiveUser()
		h := NewSeedSuperAdminHandler(
			&stubAppUserRepository{},
			&mockRegisterAdmin{registerResult: user},
			defaultRoleProvider(),
			validPolicy,
			validSvc,
			&stubAppIDGenerator{userID: testUserID()},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := h.Handle(unauthenticatedCtx(), validCmd)
		require.NoError(t, err)
	})

	t.Run("invalid_email", func(t *testing.T) {
		h := NewSeedSuperAdminHandler(
			&stubAppUserRepository{},
			&mockRegisterAdmin{},
			defaultRoleProvider(),
			validPolicy,
			validSvc,
			&stubAppIDGenerator{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := h.Handle(context.Background(), RegisterUserCommand{Email: "bad", Password: "Str0ng!Pass"})
		assert.ErrorIs(t, err, domain.ErrUserEmailInvalid)
	})

	t.Run("policy_violation", func(t *testing.T) {
		h := NewSeedSuperAdminHandler(
			&stubAppUserRepository{},
			&mockRegisterAdmin{},
			defaultRoleProvider(),
			&mockPasswordPolicy{validateErr: domain.ErrPasswordTooShort},
			validSvc,
			&stubAppIDGenerator{userID: testUserID()},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := h.Handle(context.Background(), validCmd)
		assert.ErrorIs(t, err, domain.ErrPasswordTooShort)
	})

	t.Run("id_gen_fails", func(t *testing.T) {
		h := NewSeedSuperAdminHandler(
			&stubAppUserRepository{},
			&mockRegisterAdmin{},
			defaultRoleProvider(),
			validPolicy,
			validSvc,
			&stubAppIDGenerator{userIDErr: errTest},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := h.Handle(context.Background(), validCmd)
		assert.ErrorIs(t, err, errTest)
	})

	t.Run("email_taken", func(t *testing.T) {
		h := NewSeedSuperAdminHandler(
			&stubAppUserRepository{findByEmailResult: testActiveUser()},
			&mockRegisterAdmin{},
			defaultRoleProvider(),
			validPolicy,
			validSvc,
			&stubAppIDGenerator{userID: testUserID()},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := h.Handle(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, domain.ErrUserEmailTaken)
	})

	t.Run("domain_fails", func(t *testing.T) {
		h := NewSeedSuperAdminHandler(
			&stubAppUserRepository{},
			&mockRegisterAdmin{registerErr: domain.ErrRegistrationDisabled},
			defaultRoleProvider(),
			validPolicy,
			validSvc,
			&stubAppIDGenerator{userID: testUserID()},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := h.Handle(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, domain.ErrRegistrationDisabled)
	})

	t.Run("save_fails", func(t *testing.T) {
		user := testActiveUser()
		h := NewSeedSuperAdminHandler(
			&stubAppUserRepository{saveErr: errTest},
			&mockRegisterAdmin{registerResult: user},
			defaultRoleProvider(),
			validPolicy,
			validSvc,
			&stubAppIDGenerator{userID: testUserID()},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := h.Handle(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, errTest)
	})
}
