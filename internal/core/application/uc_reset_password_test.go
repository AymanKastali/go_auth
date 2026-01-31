package application

import (
	"testing"

	"go_auth/internal/core/domain"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResetPasswordUseCase(t *testing.T) {
	validCmd := ResetPasswordCommand{Token: "raw-tok", NewPassword: "NewStr0ng!"}

	t.Run("happy_path", func(t *testing.T) {
		uc := NewResetPasswordUseCase(
			&mockAccountManager{resetErr: nil},
			&mockTransactionManager{},
			&stubClock{now: appTestNow},
		)

		err := uc.Execute(unauthenticatedCtx(), validCmd)
		require.NoError(t, err)
	})

	t.Run("empty_token", func(t *testing.T) {
		uc := NewResetPasswordUseCase(
			&mockAccountManager{},
			&mockTransactionManager{},
			&stubClock{now: appTestNow},
		)

		err := uc.Execute(unauthenticatedCtx(), ResetPasswordCommand{Token: "", NewPassword: "pass"})
		assert.ErrorIs(t, err, domain.ErrTokenInvalid)
	})

	t.Run("empty_password", func(t *testing.T) {
		uc := NewResetPasswordUseCase(
			&mockAccountManager{},
			&mockTransactionManager{},
			&stubClock{now: appTestNow},
		)

		err := uc.Execute(unauthenticatedCtx(), ResetPasswordCommand{Token: "tok", NewPassword: ""})
		assert.ErrorIs(t, err, domain.ErrUserPasswordRequired)
	})

	t.Run("domain_fails", func(t *testing.T) {
		uc := NewResetPasswordUseCase(
			&mockAccountManager{resetErr: domain.ErrRecoveryTokenInvalid},
			&mockTransactionManager{},
			&stubClock{now: appTestNow},
		)

		err := uc.Execute(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, domain.ErrRecoveryTokenInvalid)
	})
}
