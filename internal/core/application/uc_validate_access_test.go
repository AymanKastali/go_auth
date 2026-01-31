package application

import (
	"testing"

	"go_auth/internal/core/domain"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateAccessUseCase(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		user := testActiveUser()
		uc := NewValidateAccessUseCase(
			&mockAccessManager{verifyUser: user, verifySID: testSessionID()},
			&stubClock{now: appTestNow},
		)

		resp, err := uc.Execute(unauthenticatedCtx(), ValidateAccessQuery{AccessToken: "tok"})
		require.NoError(t, err)
		assert.Equal(t, "user-001", resp.UserID)
		assert.Equal(t, "sess-001", resp.SessionID)
		assert.Contains(t, resp.Roles, "member")
	})

	t.Run("empty_token", func(t *testing.T) {
		uc := NewValidateAccessUseCase(
			&mockAccessManager{},
			&stubClock{now: appTestNow},
		)

		_, err := uc.Execute(unauthenticatedCtx(), ValidateAccessQuery{AccessToken: ""})
		assert.ErrorIs(t, err, domain.ErrTokenInvalid)
	})

	t.Run("verification_fails", func(t *testing.T) {
		uc := NewValidateAccessUseCase(
			&mockAccessManager{verifyErr: domain.ErrTokenInvalid},
			&stubClock{now: appTestNow},
		)

		_, err := uc.Execute(unauthenticatedCtx(), ValidateAccessQuery{AccessToken: "bad"})
		assert.ErrorIs(t, err, domain.ErrTokenInvalid)
	})
}
