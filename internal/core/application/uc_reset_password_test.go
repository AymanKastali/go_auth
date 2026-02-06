package application

import (
	"testing"

	"go_auth/internal/core/domain"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResetPasswordUseCase(t *testing.T) {
	validCmd := ResetPasswordCommand{Token: "raw-tok", NewPassword: "NewStr0ng!"}
	recHash := domain.ReconstituteRecoveryTokenHash("recovery-hash")

	validRecovery := func() *domain.RecoveryToken {
		return domain.ReconstituteRecoveryToken(
			domain.ReconstituteRecoveryTokenID("rec-001"),
			testUserID(),
			recHash,
			appTestFuture,
			nil,
		)
	}

	makeUC := func(
		userRepo *stubAppUserRepository,
		recoveryRepo *stubAppRecoveryTokenRepository,
		accountMgr *mockAccountManager,
	) IResetPasswordUseCase {
		return NewResetPasswordUseCase(
			userRepo,
			recoveryRepo,
			&mockTokenService{hashRecoveryOut: recHash},
			accountMgr,
			&mockTransactionManager{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)
	}

	t.Run("happy_path", func(t *testing.T) {
		uc := makeUC(
			&stubAppUserRepository{findByIDResult: testActiveUser()},
			&stubAppRecoveryTokenRepository{findByHashResult: validRecovery()},
			&mockAccountManager{resetErr: nil},
		)

		err := uc.Execute(unauthenticatedCtx(), validCmd)
		require.NoError(t, err)
	})

	t.Run("empty_token", func(t *testing.T) {
		uc := makeUC(
			&stubAppUserRepository{},
			&stubAppRecoveryTokenRepository{},
			&mockAccountManager{},
		)

		err := uc.Execute(unauthenticatedCtx(), ResetPasswordCommand{Token: "", NewPassword: "pass"})
		assert.ErrorIs(t, err, domain.ErrTokenInvalid)
	})

	t.Run("empty_password", func(t *testing.T) {
		uc := makeUC(
			&stubAppUserRepository{},
			&stubAppRecoveryTokenRepository{},
			&mockAccountManager{},
		)

		err := uc.Execute(unauthenticatedCtx(), ResetPasswordCommand{Token: "tok", NewPassword: ""})
		assert.ErrorIs(t, err, domain.ErrUserPasswordRequired)
	})

	t.Run("recovery_token_not_found", func(t *testing.T) {
		uc := makeUC(
			&stubAppUserRepository{},
			&stubAppRecoveryTokenRepository{findByHashResult: nil},
			&mockAccountManager{},
		)

		err := uc.Execute(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, domain.ErrRecoveryTokenInvalid)
	})

	t.Run("user_not_found", func(t *testing.T) {
		uc := makeUC(
			&stubAppUserRepository{findByIDResult: nil},
			&stubAppRecoveryTokenRepository{findByHashResult: validRecovery()},
			&mockAccountManager{},
		)

		err := uc.Execute(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, domain.ErrUserNotFound)
	})

	t.Run("domain_fails", func(t *testing.T) {
		uc := makeUC(
			&stubAppUserRepository{findByIDResult: testActiveUser()},
			&stubAppRecoveryTokenRepository{findByHashResult: validRecovery()},
			&mockAccountManager{resetErr: domain.ErrRecoveryTokenInvalid},
		)

		err := uc.Execute(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, domain.ErrRecoveryTokenInvalid)
	})
}
