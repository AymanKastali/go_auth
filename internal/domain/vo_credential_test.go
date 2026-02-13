package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHashedPassword(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr error
	}{
		{"valid", "$2a$10$somehash", nil},
		{"empty", "", ErrUserPasswordRequired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hp, err := NewHashedPassword(tt.input)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Equal(t, ZeroHashedPassword, hp)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.input, hp.String())
				assert.False(t, hp.IsEmpty())
			}
		})
	}
}

func TestValidatedPassword(t *testing.T) {
	t.Run("reconstitute", func(t *testing.T) {
		vp := ReconstituteValidatedPassword("Str0ng!Pass")
		assert.Equal(t, "Str0ng!Pass", vp.String())
		assert.False(t, vp.IsEmpty())
	})

	t.Run("zero_value_is_empty", func(t *testing.T) {
		assert.True(t, ZeroValidatedPassword.IsEmpty())
		assert.Equal(t, "", ZeroValidatedPassword.String())
	})
}
