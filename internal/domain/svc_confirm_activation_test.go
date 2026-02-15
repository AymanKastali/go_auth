package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfirmActivation_Confirm(t *testing.T) {
	confirmer := NewConfirmActivation()

	makeActivation := func(userID UserID, expiry bool, used bool) *ActivationToken {
		exp := testFuture
		if !expiry {
			exp = testPast
		}
		return ReconstituteActivationToken(
			ReconstituteActivationTokenID("act-001"),
			userID,
			ReconstituteActivationTokenHash("hashed-activation"),
			exp,
			used,
		)
	}

	t.Run("happy_path", func(t *testing.T) {
		user := newInactiveUser()
		activation := makeActivation(validUserID(), true, false)

		err := confirmer.Confirm(user, activation, testNow)
		require.NoError(t, err)
		assert.True(t, user.IsActive())
		assert.True(t, activation.IsUsed())
	})

	t.Run("expired_token", func(t *testing.T) {
		user := newInactiveUser()
		activation := makeActivation(validUserID(), false, false)

		err := confirmer.Confirm(user, activation, testNow)
		assert.ErrorIs(t, err, ErrActivationTokenExpired)
	})

	t.Run("already_used_token", func(t *testing.T) {
		user := newInactiveUser()
		activation := makeActivation(validUserID(), true, true)

		err := confirmer.Confirm(user, activation, testNow)
		assert.ErrorIs(t, err, ErrActivationTokenAlreadyUsed)
	})

	t.Run("user_id_mismatch", func(t *testing.T) {
		user := newInactiveUser()
		otherUserID := ReconstituteUserID("other-user")
		activation := makeActivation(otherUserID, true, false)

		err := confirmer.Confirm(user, activation, testNow)
		assert.ErrorIs(t, err, ErrActivationTokenInvalid)
	})

	t.Run("user_already_active", func(t *testing.T) {
		user := newActiveUser()
		activation := makeActivation(validUserID(), true, false)

		err := confirmer.Confirm(user, activation, testNow)
		assert.ErrorIs(t, err, ErrUserAlreadyActive)
	})
}
