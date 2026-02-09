package application

import (
	"testing"

	"go_auth/internal/domain"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestForgotPasswordUseCase(t *testing.T) {
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

	rawTok, _ := domain.NewRawToken("raw-recovery")

	t.Run("happy_path", func(t *testing.T) {
		user := testActiveUser()
		emailSvc := &mockEmailService{}
		uc := NewForgotPasswordUseCase(
			&stubAppUserRepository{findByEmailResult: user},
			&stubAppRecoveryTokenRepository{},
			&mockAccountManager{initiateRawToken: rawTok, initiateRecovery: makeRecoveryToken()},
			emailSvc,
			&mockTransactionManager{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := uc.Execute(unauthenticatedCtx(), validCmd)
		require.NoError(t, err)
		assert.Equal(t, "test@example.com", emailSvc.sentTo)
		assert.Equal(t, "raw-recovery", emailSvc.sentToken)
	})

	t.Run("invalid_email", func(t *testing.T) {
		uc := NewForgotPasswordUseCase(
			&stubAppUserRepository{},
			&stubAppRecoveryTokenRepository{},
			&mockAccountManager{},
			&mockEmailService{},
			&mockTransactionManager{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := uc.Execute(unauthenticatedCtx(), ForgotPasswordCommand{Email: "bad"})
		assert.ErrorIs(t, err, domain.ErrUserEmailInvalid)
	})

	t.Run("user_not_found_returns_nil", func(t *testing.T) {
		uc := NewForgotPasswordUseCase(
			&stubAppUserRepository{findByEmailResult: nil},
			&stubAppRecoveryTokenRepository{},
			&mockAccountManager{},
			&mockEmailService{},
			&mockTransactionManager{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := uc.Execute(unauthenticatedCtx(), validCmd)
		assert.NoError(t, err) // silent for security
	})

	t.Run("initiate_fails", func(t *testing.T) {
		user := testActiveUser()
		uc := NewForgotPasswordUseCase(
			&stubAppUserRepository{findByEmailResult: user},
			&stubAppRecoveryTokenRepository{},
			&mockAccountManager{initiateErr: errTest},
			&mockEmailService{},
			&mockTransactionManager{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := uc.Execute(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, errTest)
	})

	t.Run("save_fails", func(t *testing.T) {
		user := testActiveUser()
		uc := NewForgotPasswordUseCase(
			&stubAppUserRepository{findByEmailResult: user},
			&stubAppRecoveryTokenRepository{saveErr: errTest},
			&mockAccountManager{initiateRawToken: rawTok, initiateRecovery: makeRecoveryToken()},
			&mockEmailService{},
			&mockTransactionManager{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := uc.Execute(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, errTest)
	})

	t.Run("email_fails", func(t *testing.T) {
		user := testActiveUser()
		uc := NewForgotPasswordUseCase(
			&stubAppUserRepository{findByEmailResult: user},
			&stubAppRecoveryTokenRepository{},
			&mockAccountManager{initiateRawToken: rawTok, initiateRecovery: makeRecoveryToken()},
			&mockEmailService{err: errTest},
			&mockTransactionManager{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		err := uc.Execute(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, errTest)
	})
}
