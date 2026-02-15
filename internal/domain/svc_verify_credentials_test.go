package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyCredentials_Verify(t *testing.T) {
	makeVerifier := func(pwdMatch bool) IVerifyCredentials {
		return NewVerifyCredentials(
			&stubPasswordService{compareOut: pwdMatch},
		)
	}

	t.Run("valid_credentials", func(t *testing.T) {
		svc := makeVerifier(true)
		user := newActiveUser()

		err := svc.Verify(user, "pass")
		require.NoError(t, err)
	})

	t.Run("wrong_password", func(t *testing.T) {
		svc := makeVerifier(false)
		user := newActiveUser()

		err := svc.Verify(user, "wrong")
		assert.ErrorIs(t, err, ErrAuthenticationFailed)
	})

	t.Run("inactive_user", func(t *testing.T) {
		svc := makeVerifier(true)
		user := newInactiveUser()

		err := svc.Verify(user, "pass")
		assert.ErrorIs(t, err, ErrUserInactive)
	})
}
