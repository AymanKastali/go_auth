package domain

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSessionID(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr error
	}{
		{"valid", "sess-abc", nil},
		{"empty", "", ErrSessionIDRequired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sid, err := NewSessionID(tt.input)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Equal(t, ZeroSessionID, sid)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.input, sid.String())
				assert.False(t, sid.IsEmpty())
			}
		})
	}
}

func TestSessionID_Equal(t *testing.T) {
	a := ReconstituteSessionID("s1")
	b := ReconstituteSessionID("s1")
	c := ReconstituteSessionID("s2")
	assert.True(t, a.Equal(b))
	assert.False(t, a.Equal(c))
}

func TestNewHashedToken(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr error
	}{
		{"valid", "hashed-abc", nil},
		{"empty", "", ErrTokenInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ht, err := NewHashedToken(tt.input)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.input, ht.String())
			}
		})
	}
}

func TestNewAccessToken(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr error
	}{
		{"valid", "eyJhbGciOi...", nil},
		{"empty", "", ErrTokenInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			at, err := NewAccessToken(tt.input)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.input, at.String())
			}
		})
	}
}

func TestNewSessionExpiry(t *testing.T) {
	now := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)

	t.Run("valid_future", func(t *testing.T) {
		future := now.Add(24 * time.Hour)
		exp, err := NewSessionExpiry(future, now)
		require.NoError(t, err)
		assert.Equal(t, future, exp.Time())
		assert.False(t, exp.IsZero())
		assert.False(t, exp.IsExpired(now))
	})

	t.Run("expired_in_past", func(t *testing.T) {
		past := now.Add(-1 * time.Hour)
		exp, err := NewSessionExpiry(past, now)
		assert.ErrorIs(t, err, ErrSessionExpiryInvalid)
		assert.Equal(t, ZeroSessionExpiry, exp)
	})

	t.Run("equal_to_now", func(t *testing.T) {
		exp, err := NewSessionExpiry(now, now)
		assert.ErrorIs(t, err, ErrSessionExpiryInvalid)
		assert.Equal(t, ZeroSessionExpiry, exp)
	})

	t.Run("is_expired_check", func(t *testing.T) {
		future := now.Add(1 * time.Hour)
		exp, _ := NewSessionExpiry(future, now)
		assert.False(t, exp.IsExpired(now))
		assert.True(t, exp.IsExpired(future))
		assert.True(t, exp.IsExpired(future.Add(1*time.Second)))
	})
}

func TestNewAccessIdentity(t *testing.T) {
	uid := ReconstituteUserID("u1")
	sid := ReconstituteSessionID("s1")
	email := ReconstituteEmail("a@b.com")
	roles := []RoleName{ReconstituteRoleName("member")}

	t.Run("valid", func(t *testing.T) {
		ai, err := NewAccessIdentity(uid, sid, email, roles, nil)
		require.NoError(t, err)
		assert.Equal(t, uid, ai.UserID())
		assert.Equal(t, sid, ai.SessionID())
		assert.Equal(t, email, ai.Email())
		assert.Equal(t, roles, ai.Roles())
	})

	t.Run("empty_userID", func(t *testing.T) {
		_, err := NewAccessIdentity(ZeroUserID, sid, email, roles, nil)
		assert.ErrorIs(t, err, ErrAccessIdentityIncomplete)
	})

	t.Run("empty_sessionID", func(t *testing.T) {
		_, err := NewAccessIdentity(uid, ZeroSessionID, email, roles, nil)
		assert.ErrorIs(t, err, ErrAccessIdentityIncomplete)
	})

	t.Run("empty_email", func(t *testing.T) {
		_, err := NewAccessIdentity(uid, sid, ZeroEmail, roles, nil)
		assert.ErrorIs(t, err, ErrAccessIdentityIncomplete)
	})

	t.Run("empty_roles", func(t *testing.T) {
		_, err := NewAccessIdentity(uid, sid, email, nil, nil)
		assert.ErrorIs(t, err, ErrAccessIdentityIncomplete)
	})
}
