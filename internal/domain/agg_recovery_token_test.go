package domain

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRecoveryToken(t *testing.T) {
	id := ReconstituteRecoveryTokenID("rec-001")
	uid := validUserID()
	hash := ReconstituteRecoveryTokenHash("hash-001")

	t.Run("valid", func(t *testing.T) {
		rt, err := NewRecoveryToken(id, uid, hash, testFuture, testNow)
		require.NoError(t, err)
		assert.Equal(t, id, rt.ID())
		assert.Equal(t, uid, rt.UserID())
		assert.Equal(t, hash, rt.HashedToken())
		assert.False(t, rt.IsUsed())

		events := rt.CollectEvents()
		assertEventRecorded(t, events, "PasswordResetRequested")
	})

	t.Run("empty_userID", func(t *testing.T) {
		_, err := NewRecoveryToken(id, ZeroUserID, hash, testFuture, testNow)
		assert.ErrorIs(t, err, ErrUserIDRequired)
	})

	t.Run("expired", func(t *testing.T) {
		_, err := NewRecoveryToken(id, uid, hash, testPast, testNow)
		assert.ErrorIs(t, err, ErrSessionExpiryInPast)
	})
}

func TestRecoveryToken_IsValid(t *testing.T) {
	id := ReconstituteRecoveryTokenID("rec-001")
	uid := validUserID()
	hash := ReconstituteRecoveryTokenHash("hash-001")

	tests := []struct {
		name     string
		used     bool
		checkAt  time.Time
		expected bool
	}{
		{"valid_not_used_not_expired", false, testNow, true},
		{"used", true, testNow, false},
		{"expired", false, testFarFuture, false},
		{"used_and_expired", true, testFarFuture, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := ReconstituteRecoveryToken(id, uid, hash, testFuture, tt.used)
			assert.Equal(t, tt.expected, rt.IsValid(tt.checkAt))
		})
	}
}

func TestRecoveryToken_MarkAsUsed(t *testing.T) {
	id := ReconstituteRecoveryTokenID("rec-001")
	uid := validUserID()
	hash := ReconstituteRecoveryTokenHash("hash-001")

	t.Run("first_use", func(t *testing.T) {
		rt := ReconstituteRecoveryToken(id, uid, hash, testFuture, false)
		err := rt.MarkAsUsed(testNow)
		require.NoError(t, err)
		assert.True(t, rt.IsUsed())

		events := rt.CollectEvents()
		assertEventRecorded(t, events, "RecoveryTokenUsed")
	})

	t.Run("double_use", func(t *testing.T) {
		rt := ReconstituteRecoveryToken(id, uid, hash, testFuture, false)
		_ = rt.MarkAsUsed(testNow)
		_ = rt.CollectEvents() // drain
		err := rt.MarkAsUsed(testNow)
		assert.ErrorIs(t, err, ErrRecoveryTokenRevoked)
	})
}
