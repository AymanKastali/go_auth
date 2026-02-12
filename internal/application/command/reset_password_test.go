package command

import (
	"testing"

	"go_auth/internal/domain"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResetPasswordHandler(t *testing.T) {
	validCmd := ResetPasswordCommand{Token: "raw-tok", NewPassword: "NewStr0ng!"}
	recHash := domain.ReconstituteRecoveryTokenHash("recovery-hash")

	validRecovery := func() *domain.RecoveryToken {
		return domain.ReconstituteRecoveryToken(
			domain.ReconstituteRecoveryTokenID("rec-001"),
			testUserID(),
			recHash,
			appTestFuture,
			false,
		)
	}

	makeHandler := func(
		userRepo *stubAppUserRepository,
		sessionRepo *stubAppSessionRepository,
		recoveryRepo *stubAppRecoveryTokenRepository,
		accountMgr *mockAccountManager,
	) IResetPasswordHandler {
		return NewResetPasswordHandler(
			userRepo,
			sessionRepo,
			recoveryRepo,
			&mockTokenService{hashRecoveryOut: recHash},
			accountMgr,
			&mockTransactionManager{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)
	}

	t.Run("happy_path", func(t *testing.T) {
		h := makeHandler(
			&stubAppUserRepository{findByIDResult: testActiveUser()},
			&stubAppSessionRepository{},
			&stubAppRecoveryTokenRepository{findByHashResult: validRecovery()},
			&mockAccountManager{resetErr: nil},
		)

		err := h.Handle(unauthenticatedCtx(), validCmd)
		require.NoError(t, err)
	})

	t.Run("empty_token", func(t *testing.T) {
		h := makeHandler(
			&stubAppUserRepository{},
			&stubAppSessionRepository{},
			&stubAppRecoveryTokenRepository{},
			&mockAccountManager{},
		)

		err := h.Handle(unauthenticatedCtx(), ResetPasswordCommand{Token: "", NewPassword: "pass"})
		assert.ErrorIs(t, err, domain.ErrTokenInvalid)
	})

	t.Run("empty_password", func(t *testing.T) {
		h := makeHandler(
			&stubAppUserRepository{},
			&stubAppSessionRepository{},
			&stubAppRecoveryTokenRepository{},
			&mockAccountManager{},
		)

		err := h.Handle(unauthenticatedCtx(), ResetPasswordCommand{Token: "tok", NewPassword: ""})
		assert.ErrorIs(t, err, domain.ErrUserPasswordRequired)
	})

	t.Run("recovery_token_not_found", func(t *testing.T) {
		h := makeHandler(
			&stubAppUserRepository{},
			&stubAppSessionRepository{},
			&stubAppRecoveryTokenRepository{findByHashResult: nil},
			&mockAccountManager{},
		)

		err := h.Handle(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, domain.ErrRecoveryTokenInvalid)
	})

	t.Run("user_not_found", func(t *testing.T) {
		h := makeHandler(
			&stubAppUserRepository{findByIDResult: nil},
			&stubAppSessionRepository{},
			&stubAppRecoveryTokenRepository{findByHashResult: validRecovery()},
			&mockAccountManager{},
		)

		err := h.Handle(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, domain.ErrUserNotFound)
	})

	t.Run("domain_fails", func(t *testing.T) {
		h := makeHandler(
			&stubAppUserRepository{findByIDResult: testActiveUser()},
			&stubAppSessionRepository{},
			&stubAppRecoveryTokenRepository{findByHashResult: validRecovery()},
			&mockAccountManager{resetErr: domain.ErrRecoveryTokenInvalid},
		)

		err := h.Handle(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, domain.ErrRecoveryTokenInvalid)
	})
}
