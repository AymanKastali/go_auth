package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSession(t *testing.T) {
	sid := validSessionID()
	ht := validHashedToken()
	di := validDeviceIdentity()

	t.Run("valid", func(t *testing.T) {
		s, err := NewSession(sid, ht, di, testFuture, testNow)
		require.NoError(t, err)
		assert.Equal(t, sid, s.ID())
		assert.Equal(t, ht, s.HashedToken())
		assert.Equal(t, di.Fingerprint(), s.Identity().Fingerprint())
		assert.True(t, s.ExpiresAt().Equal(testFuture))
		assert.True(t, s.LastActiveAt().Equal(testNow))
		assert.False(t, s.IsRevoked())
	})

	t.Run("empty_id", func(t *testing.T) {
		_, err := NewSession(ZeroSessionID, ht, di, testFuture, testNow)
		assert.ErrorIs(t, err, ErrSessionIDRequired)
	})

	t.Run("expired", func(t *testing.T) {
		_, err := NewSession(sid, ht, di, testPast, testNow)
		assert.ErrorIs(t, err, ErrSessionExpiryInPast)
	})
}

func TestSession_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		revoked  bool
		checkAt  Timepoint
		expected bool
	}{
		{"active_not_expired", false, testNow, true},
		{"active_expired", false, testFarFuture, false},
		{"revoked_not_expired", true, testNow, false},
		{"revoked_expired", true, testFarFuture, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var revAt *Timepoint
			if tt.revoked {
				revAt = &testPast
			}
			s := ReconstituteSession(validSessionID(), validHashedToken(), validDeviceIdentity(), testFuture, testNow, revAt)
			assert.Equal(t, tt.expected, s.IsValid(tt.checkAt))
		})
	}
}

func TestSession_ValidateFingerprint(t *testing.T) {
	s := ReconstituteSession(validSessionID(), validHashedToken(), validDeviceIdentity(), testFuture, testNow, nil)
	match := validDeviceIdentity().Fingerprint()
	mismatch := differentDeviceIdentity().Fingerprint()

	assert.True(t, s.ValidateFingerprint(match))
	assert.False(t, s.ValidateFingerprint(mismatch))
}

func TestSession_Revoke(t *testing.T) {
	t.Run("first_revoke", func(t *testing.T) {
		s := ReconstituteSession(validSessionID(), validHashedToken(), validDeviceIdentity(), testFuture, testNow, nil)
		err := s.Revoke(testNow)
		require.NoError(t, err)
		assert.True(t, s.IsRevoked())
	})

	t.Run("double_revoke", func(t *testing.T) {
		s := ReconstituteSession(validSessionID(), validHashedToken(), validDeviceIdentity(), testFuture, testNow, nil)
		_ = s.Revoke(testNow)
		err := s.Revoke(testNow)
		assert.ErrorIs(t, err, ErrSessionAlreadyRevoked)
	})
}

func TestSession_UpdateLogin(t *testing.T) {
	s := ReconstituteSession(validSessionID(), validHashedToken(), validDeviceIdentity(), testFuture, testNow, nil)
	newToken := ReconstituteHashedToken("new-hash")
	s.UpdateLogin(newToken, testFarFuture, testFuture)
	assert.Equal(t, newToken, s.HashedToken())
	assert.True(t, s.ExpiresAt().Equal(testFarFuture))
	assert.True(t, s.LastActiveAt().Equal(testFuture))
}

func TestSession_UpdateActivity(t *testing.T) {
	s := ReconstituteSession(validSessionID(), validHashedToken(), validDeviceIdentity(), testFuture, testNow, nil)
	s.UpdateActivity(testFuture)
	assert.True(t, s.LastActiveAt().Equal(testFuture))
}
