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

func TestNewRawPassword(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr error
	}{
		{"valid", "S3cure!Pass", nil},
		{"empty", "", ErrUserPasswordRequired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rp, err := NewRawPassword(tt.input)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Equal(t, ZeroRawPassword, rp)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.input, rp.String())
				assert.False(t, rp.IsEmpty())
			}
		})
	}
}
