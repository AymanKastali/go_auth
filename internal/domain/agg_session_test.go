package domain

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSession(t *testing.T) {
	sid := validSessionID()
	uid := validUserID()
	ht := validHashedToken()
	di := validDeviceIdentity()
	expiry := ReconstituteSessionExpiry(testFuture)

	t.Run("valid", func(t *testing.T) {
		s, err := NewSession(sid, uid, ht, di, expiry, testNow)
		require.NoError(t, err)
		assert.Equal(t, sid, s.ID())
		assert.Equal(t, uid, s.UserID())
		assert.Equal(t, ht, s.HashedToken())
		assert.Equal(t, di.Fingerprint(), s.Identity().Fingerprint())
		assert.True(t, s.Expiry().Time().Equal(testFuture))
		assert.True(t, s.LastActiveAt().Equal(testNow))
		assert.False(t, s.IsRevoked())

		events := s.CollectEvents()
		assertEventRecorded(t, events, "SessionEstablished")
		assertEventCount(t, events, 1)
	})

	t.Run("empty_id", func(t *testing.T) {
		_, err := NewSession(ZeroSessionID, uid, ht, di, expiry, testNow)
		assert.ErrorIs(t, err, ErrSessionIDRequired)
	})

	t.Run("empty_user_id", func(t *testing.T) {
		_, err := NewSession(sid, ZeroUserID, ht, di, expiry, testNow)
		assert.ErrorIs(t, err, ErrSessionUserIDRequired)
	})
}

func TestSession_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		revoked  bool
		checkAt  time.Time
		expected bool
	}{
		{"active_not_expired", false, testNow, true},
		{"active_expired", false, testFarFuture, false},
		{"revoked_not_expired", true, testNow, false},
		{"revoked_expired", true, testFarFuture, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := ReconstituteSession(validSessionID(), validUserID(), validHashedToken(), ZeroHashedToken, validDeviceIdentity(), testFuture, testNow, tt.revoked)
			assert.Equal(t, tt.expected, s.IsValid(tt.checkAt))
		})
	}
}

func TestSession_ValidateFingerprint(t *testing.T) {
	s := ReconstituteSession(validSessionID(), validUserID(), validHashedToken(), ZeroHashedToken, validDeviceIdentity(), testFuture, testNow, false)
	match := validDeviceIdentity().Fingerprint()
	mismatch := differentDeviceIdentity().Fingerprint()

	assert.True(t, s.ValidateFingerprint(match))
	assert.False(t, s.ValidateFingerprint(mismatch))
}

func TestSession_Revoke(t *testing.T) {
	t.Run("first_revoke", func(t *testing.T) {
		s := ReconstituteSession(validSessionID(), validUserID(), validHashedToken(), ZeroHashedToken, validDeviceIdentity(), testFuture, testNow, false)
		err := s.Revoke(testNow)
		require.NoError(t, err)
		assert.True(t, s.IsRevoked())

		events := s.CollectEvents()
		assertEventRecorded(t, events, "SessionRevoked")
	})

	t.Run("double_revoke", func(t *testing.T) {
		s := ReconstituteSession(validSessionID(), validUserID(), validHashedToken(), ZeroHashedToken, validDeviceIdentity(), testFuture, testNow, false)
		_ = s.Revoke(testNow)
		err := s.Revoke(testNow)
		assert.ErrorIs(t, err, ErrSessionAlreadyRevoked)
	})
}

func TestSession_UpdateLogin(t *testing.T) {
	s := ReconstituteSession(validSessionID(), validUserID(), validHashedToken(), ZeroHashedToken, validDeviceIdentity(), testFuture, testNow, false)
	newToken := ReconstituteHashedToken("new-hash")
	newExpiry := ReconstituteSessionExpiry(testFarFuture)
	s.UpdateLogin(newToken, newExpiry, testFuture)
	assert.Equal(t, newToken, s.HashedToken())
	assert.True(t, s.PreviousHashedToken().IsEmpty())
	assert.True(t, s.Expiry().Time().Equal(testFarFuture))
	assert.True(t, s.LastActiveAt().Equal(testFuture))

	events := s.CollectEvents()
	assertEventRecorded(t, events, "SessionLoginRenewed")
	assertEventNotRecorded(t, events, "SessionEstablished")
}

func TestSession_Refresh(t *testing.T) {
	t.Run("happy_path_with_rotation", func(t *testing.T) {
		oldToken := validHashedToken()
		s := ReconstituteSession(validSessionID(), validUserID(), oldToken, ZeroHashedToken, validDeviceIdentity(), testFuture, testNow, false)
		fp := validDeviceIdentity().Fingerprint()
		newToken := ReconstituteHashedToken("new-rotated-token")
		newExpiry := ReconstituteSessionExpiry(testNow.Add(24 * time.Hour))

		err := s.Refresh(newToken, fp, newExpiry, testNow)
		require.NoError(t, err)

		assert.Equal(t, newToken, s.HashedToken())
		assert.Equal(t, oldToken, s.PreviousHashedToken())
		assert.True(t, s.Expiry().Time().Equal(testNow.Add(24*time.Hour)))
		assert.True(t, s.LastActiveAt().Equal(testNow))

		events := s.CollectEvents()
		assertEventRecorded(t, events, "SessionTokenRotated")
		assertEventRecorded(t, events, "SessionRefreshed")
		assertEventCount(t, events, 2)
	})

	t.Run("fingerprint_mismatch_hijack", func(t *testing.T) {
		s := ReconstituteSession(validSessionID(), validUserID(), validHashedToken(), ZeroHashedToken, validDeviceIdentity(), testFuture, testNow, false)
		wrongFP := differentDeviceIdentity().Fingerprint()
		newToken := ReconstituteHashedToken("new-rotated-token")
		newExpiry := ReconstituteSessionExpiry(testNow.Add(24 * time.Hour))
		err := s.Refresh(newToken, wrongFP, newExpiry, testNow)
		assert.ErrorIs(t, err, ErrSessionFingerprintMiss)
		assert.True(t, s.IsRevoked())

		events := s.CollectEvents()
		assertEventRecorded(t, events, "SessionHijackDetected")
	})

	t.Run("expired_session", func(t *testing.T) {
		s := ReconstituteSession(validSessionID(), validUserID(), validHashedToken(), ZeroHashedToken, validDeviceIdentity(), testPast, testPast, false)
		fp := validDeviceIdentity().Fingerprint()
		newToken := ReconstituteHashedToken("new-rotated-token")
		newExpiry := ReconstituteSessionExpiry(testNow.Add(24 * time.Hour))
		err := s.Refresh(newToken, fp, newExpiry, testNow)
		assert.ErrorIs(t, err, ErrSessionExpired)
	})
}

func TestSession_RevokeForTokenReuse(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		s := ReconstituteSession(validSessionID(), validUserID(), validHashedToken(), ZeroHashedToken, validDeviceIdentity(), testFuture, testNow, false)

		err := s.RevokeForTokenReuse(testNow)
		require.NoError(t, err)
		assert.True(t, s.IsRevoked())

		events := s.CollectEvents()
		assertEventRecorded(t, events, "SessionTokenReuseDetected")
		assertEventRecorded(t, events, "SessionRevoked")
		assertEventCount(t, events, 2)
	})

	t.Run("already_revoked", func(t *testing.T) {
		s := ReconstituteSession(validSessionID(), validUserID(), validHashedToken(), ZeroHashedToken, validDeviceIdentity(), testFuture, testNow, true)

		err := s.RevokeForTokenReuse(testNow)
		assert.ErrorIs(t, err, ErrSessionAlreadyRevoked)
	})
}

func TestSession_UpdateActivity(t *testing.T) {
	s := ReconstituteSession(validSessionID(), validUserID(), validHashedToken(), ZeroHashedToken, validDeviceIdentity(), testFuture, testNow, false)
	s.UpdateActivity(testFuture)
	assert.True(t, s.LastActiveAt().Equal(testFuture))
}
