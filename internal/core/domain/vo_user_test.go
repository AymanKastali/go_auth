package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewUserID(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr error
	}{
		{"valid", "user-123", nil},
		{"empty", "", ErrUserIDRequired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := NewUserID(tt.input)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Equal(t, ZeroUserID, id)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.input, id.String())
				assert.False(t, id.IsEmpty())
			}
		})
	}
}

func TestUserID_Equal(t *testing.T) {
	a := ReconstituteUserID("u1")
	b := ReconstituteUserID("u1")
	c := ReconstituteUserID("u2")
	assert.True(t, a.Equal(b))
	assert.False(t, a.Equal(c))
}

func TestNewEmail(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr error
	}{
		{"valid simple", "user@example.com", nil},
		{"valid with plus", "user+tag@example.co.uk", nil},
		{"empty", "", ErrUserEmailRequired},
		{"invalid no at", "invalid-email", ErrUserEmailInvalid},
		{"invalid no domain", "user@", ErrUserEmailInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email, err := NewEmail(tt.input)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Equal(t, ZeroEmail, email)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.input, email.String())
				assert.False(t, email.IsEmpty())
			}
		})
	}
}

func TestEmail_Equal(t *testing.T) {
	a := ReconstituteEmail("a@b.com")
	b := ReconstituteEmail("a@b.com")
	c := ReconstituteEmail("c@d.com")
	assert.True(t, a.Equal(b))
	assert.False(t, a.Equal(c))
}
