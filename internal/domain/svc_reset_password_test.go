package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResetPassword_Reset(t *testing.T) {
	recID := ReconstituteRecoveryTokenID("rec-001")
	recHash := ReconstituteRecoveryTokenHash("recovery-hash")

	t.Run("happy_path", func(t *testing.T) {
		user := newActiveUser()
		recovery := ReconstituteRecoveryToken(recID, validUserID(), recHash, testFuture, false)

		resetter := NewResetPassword(
			&stubPasswordService{hashResult: ReconstituteHashedPassword("new-hash")},
		)

		err := resetter.Reset(user, recovery, ReconstituteValidatedPassword("NewPass1!"), testNow)
		require.NoError(t, err)
		assert.True(t, recovery.IsUsed())
		assert.Equal(t, "new-hash", user.HashedPassword().String())
	})

	t.Run("recovery_expired", func(t *testing.T) {
		user := newActiveUser()
		recovery := ReconstituteRecoveryToken(recID, validUserID(), recHash, testPast, false)

		resetter := NewResetPassword(&stubPasswordService{})

		err := resetter.Reset(user, recovery, ReconstituteValidatedPassword("pass"), testNow)
		assert.ErrorIs(t, err, ErrRecoveryTokenInvalid)
	})

	t.Run("recovery_already_used", func(t *testing.T) {
		user := newActiveUser()
		recovery := ReconstituteRecoveryToken(recID, validUserID(), recHash, testFuture, true)

		resetter := NewResetPassword(&stubPasswordService{})

		err := resetter.Reset(user, recovery, ReconstituteValidatedPassword("pass"), testNow)
		assert.ErrorIs(t, err, ErrRecoveryTokenInvalid)
	})

	t.Run("user_id_mismatch", func(t *testing.T) {
		user := newActiveUser()
		otherUserID := ReconstituteUserID("other-user")
		recovery := ReconstituteRecoveryToken(recID, otherUserID, recHash, testFuture, false)

		resetter := NewResetPassword(&stubPasswordService{})

		err := resetter.Reset(user, recovery, ReconstituteValidatedPassword("pass"), testNow)
		assert.ErrorIs(t, err, ErrInvalidRecoveryAttempt)
	})

	t.Run("hash_fails", func(t *testing.T) {
		user := newActiveUser()
		recovery := ReconstituteRecoveryToken(recID, validUserID(), recHash, testFuture, false)

		resetter := NewResetPassword(
			&stubPasswordService{hashErr: ErrInternal},
		)

		err := resetter.Reset(user, recovery, ReconstituteValidatedPassword("s"), testNow)
		assert.ErrorIs(t, err, ErrInternal)
	})
}
