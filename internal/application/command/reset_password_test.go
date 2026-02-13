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

	validPolicy := &mockPasswordPolicy{
		validateResult: domain.ReconstituteValidatedPassword("NewStr0ng!"),
	}

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
		policy *mockPasswordPolicy,
		resetter *mockResetPassword,
	) IResetPasswordHandler {
		return NewResetPasswordHandler(
			userRepo,
			sessionRepo,
			recoveryRepo,
			&mockTokenService{hashRecoveryOut: recHash},
			policy,
			resetter,
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
			validPolicy,
			&mockResetPassword{err: nil},
		)

		err := h.Handle(unauthenticatedCtx(), validCmd)
		require.NoError(t, err)
	})

	t.Run("empty_token", func(t *testing.T) {
		h := makeHandler(
			&stubAppUserRepository{},
			&stubAppSessionRepository{},
			&stubAppRecoveryTokenRepository{},
			validPolicy,
			&mockResetPassword{},
		)

		err := h.Handle(unauthenticatedCtx(), ResetPasswordCommand{Token: "", NewPassword: "pass"})
		assert.ErrorIs(t, err, domain.ErrTokenInvalid)
	})

	t.Run("password_policy_fails", func(t *testing.T) {
		h := makeHandler(
			&stubAppUserRepository{},
			&stubAppSessionRepository{},
			&stubAppRecoveryTokenRepository{},
			&mockPasswordPolicy{validateErr: domain.ErrPasswordTooShort},
			&mockResetPassword{},
		)

		err := h.Handle(unauthenticatedCtx(), ResetPasswordCommand{Token: "tok", NewPassword: "short"})
		assert.ErrorIs(t, err, domain.ErrPasswordTooShort)
	})

	t.Run("recovery_token_not_found", func(t *testing.T) {
		h := makeHandler(
			&stubAppUserRepository{},
			&stubAppSessionRepository{},
			&stubAppRecoveryTokenRepository{findByHashResult: nil},
			validPolicy,
			&mockResetPassword{},
		)

		err := h.Handle(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, domain.ErrRecoveryTokenInvalid)
	})

	t.Run("user_not_found", func(t *testing.T) {
		h := makeHandler(
			&stubAppUserRepository{findByIDResult: nil},
			&stubAppSessionRepository{},
			&stubAppRecoveryTokenRepository{findByHashResult: validRecovery()},
			validPolicy,
			&mockResetPassword{},
		)

		err := h.Handle(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, domain.ErrUserNotFound)
	})

	t.Run("domain_fails", func(t *testing.T) {
		h := makeHandler(
			&stubAppUserRepository{findByIDResult: testActiveUser()},
			&stubAppSessionRepository{},
			&stubAppRecoveryTokenRepository{findByHashResult: validRecovery()},
			validPolicy,
			&mockResetPassword{err: domain.ErrRecoveryTokenInvalid},
		)

		err := h.Handle(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, domain.ErrRecoveryTokenInvalid)
	})
}
