package command

import (
	"context"
	"testing"

	"go_auth/internal/domain"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegisterHandler(t *testing.T) {
	validCmd := RegisterUserCommand{Email: "new@example.com", Password: "Str0ng!Pass"}

	validPolicy := &mockPasswordPolicy{
		validateResult: domain.ReconstituteValidatedPassword("Str0ng!Pass"),
	}
	validSvc := &mockPasswordService{hashResult: testHashedPassword()}

	t.Run("happy_path", func(t *testing.T) {
		user := testActiveUser()
		h := NewRegisterHandler(
			&stubAppUserRepository{},
			&mockRegisterMember{registerResult: user},
			validPolicy,
			validSvc,
			&stubAppIDGenerator{userID: testUserID()},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
			&mockInitiateActivation{},
			nil,
			&mockEmailService{},
			&mockTransactionManager{},
		)

		resp, err := h.Handle(unauthenticatedCtx(), validCmd)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.UserID)
		assert.NotEmpty(t, resp.Email)
	})

	t.Run("invalid_email", func(t *testing.T) {
		h := NewRegisterHandler(
			&stubAppUserRepository{},
			&mockRegisterMember{},
			validPolicy,
			validSvc,
			&stubAppIDGenerator{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
			&mockInitiateActivation{},
			nil,
			&mockEmailService{},
			&mockTransactionManager{},
		)

		_, err := h.Handle(context.Background(), RegisterUserCommand{Email: "bad", Password: "Str0ng!Pass"})
		assert.ErrorIs(t, err, domain.ErrUserEmailInvalid)
	})

	t.Run("policy_violation", func(t *testing.T) {
		h := NewRegisterHandler(
			&stubAppUserRepository{},
			&mockRegisterMember{},
			&mockPasswordPolicy{validateErr: domain.ErrPasswordTooShort},
			validSvc,
			&stubAppIDGenerator{userID: testUserID()},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
			&mockInitiateActivation{},
			nil,
			&mockEmailService{},
			&mockTransactionManager{},
		)

		_, err := h.Handle(context.Background(), validCmd)
		assert.ErrorIs(t, err, domain.ErrPasswordTooShort)
	})

	t.Run("id_gen_fails", func(t *testing.T) {
		h := NewRegisterHandler(
			&stubAppUserRepository{},
			&mockRegisterMember{},
			validPolicy,
			validSvc,
			&stubAppIDGenerator{userIDErr: errTest},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
			&mockInitiateActivation{},
			nil,
			&mockEmailService{},
			&mockTransactionManager{},
		)

		_, err := h.Handle(context.Background(), validCmd)
		assert.ErrorIs(t, err, errTest)
	})

	t.Run("email_taken", func(t *testing.T) {
		h := NewRegisterHandler(
			&stubAppUserRepository{},
			&mockRegisterMember{registerErr: domain.ErrUserEmailTaken},
			validPolicy,
			validSvc,
			&stubAppIDGenerator{userID: testUserID()},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
			&mockInitiateActivation{},
			nil,
			&mockEmailService{},
			&mockTransactionManager{},
		)

		_, err := h.Handle(context.Background(), validCmd)
		assert.ErrorIs(t, err, domain.ErrUserEmailTaken)
	})

	t.Run("save_fails", func(t *testing.T) {
		user := testActiveUser()
		h := NewRegisterHandler(
			&stubAppUserRepository{saveErr: errTest},
			&mockRegisterMember{registerResult: user},
			validPolicy,
			validSvc,
			&stubAppIDGenerator{userID: testUserID()},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
			&mockInitiateActivation{},
			nil,
			&mockEmailService{},
			&mockTransactionManager{},
		)

		_, err := h.Handle(context.Background(), validCmd)
		assert.ErrorIs(t, err, errTest)
	})
}
