package command

import (
	"testing"

	"go_auth/internal/domain"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestForgotPasswordHandler(t *testing.T) {
	validCmd := ForgotPasswordCommand{Email: "test@example.com"}

	makeRecoveryToken := func() *domain.RecoveryToken {
		return domain.ReconstituteRecoveryToken(
			domain.ReconstituteRecoveryTokenID("rec-001"),
			testUserID(),
			domain.ReconstituteRecoveryTokenHash("hash"),
			appTestFuture,
			false,
		)
	}

	rawTok := "raw-recovery"

	t.Run("happy_path", func(t *testing.T) {
		user := testActiveUser()
		emailSvc := &mockEmailService{}
		h := NewForgotPasswordHandler(
			&stubAppUserRepository{findByEmailResult: user},
			&stubAppRecoveryTokenRepository{},
			&mockInitiateRecovery{rawToken: rawTok, recovery: makeRecoveryToken()},
			emailSvc,
			&mockTransactionManager{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := h.Handle(unauthenticatedCtx(), validCmd)
		require.NoError(t, err)
		assert.Equal(t, "test@example.com", emailSvc.sentTo)
		assert.Equal(t, "raw-recovery", emailSvc.sentToken)
	})

	t.Run("invalid_email", func(t *testing.T) {
		h := NewForgotPasswordHandler(
			&stubAppUserRepository{},
			&stubAppRecoveryTokenRepository{},
			&mockInitiateRecovery{},
			&mockEmailService{},
			&mockTransactionManager{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := h.Handle(unauthenticatedCtx(), ForgotPasswordCommand{Email: "bad"})
		assert.ErrorIs(t, err, domain.ErrUserEmailInvalid)
	})

	t.Run("user_not_found_returns_nil", func(t *testing.T) {
		h := NewForgotPasswordHandler(
			&stubAppUserRepository{findByEmailResult: nil},
			&stubAppRecoveryTokenRepository{},
			&mockInitiateRecovery{},
			&mockEmailService{},
			&mockTransactionManager{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := h.Handle(unauthenticatedCtx(), validCmd)
		assert.NoError(t, err) // silent for security
	})

	t.Run("initiate_fails", func(t *testing.T) {
		user := testActiveUser()
		h := NewForgotPasswordHandler(
			&stubAppUserRepository{findByEmailResult: user},
			&stubAppRecoveryTokenRepository{},
			&mockInitiateRecovery{err: errTest},
			&mockEmailService{},
			&mockTransactionManager{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := h.Handle(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, errTest)
	})

	t.Run("save_fails", func(t *testing.T) {
		user := testActiveUser()
		h := NewForgotPasswordHandler(
			&stubAppUserRepository{findByEmailResult: user},
			&stubAppRecoveryTokenRepository{saveErr: errTest},
			&mockInitiateRecovery{rawToken: rawTok, recovery: makeRecoveryToken()},
			&mockEmailService{},
			&mockTransactionManager{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := h.Handle(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, errTest)
	})

	t.Run("email_fails", func(t *testing.T) {
		user := testActiveUser()
		h := NewForgotPasswordHandler(
			&stubAppUserRepository{findByEmailResult: user},
			&stubAppRecoveryTokenRepository{},
			&mockInitiateRecovery{rawToken: rawTok, recovery: makeRecoveryToken()},
			&mockEmailService{err: errTest},
			&mockTransactionManager{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := h.Handle(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, errTest)
	})
}
