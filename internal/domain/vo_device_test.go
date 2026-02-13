package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDeviceIdentity(t *testing.T) {
	tests := []struct {
		name    string
		ip, ua  string
		wantErr error
	}{
		{"valid", "192.168.1.1", "Mozilla/5.0", nil},
		{"empty_ip", "", "Mozilla/5.0", ErrDeviceIPRequired},
		{"empty_ua", "192.168.1.1", "", ErrDeviceUARequired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			di, err := NewDeviceIdentity(tt.ip, "Linux", "Chrome", "Desktop", "en", tt.ua, false)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Equal(t, ZeroDeviceIdentity, di)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.ip, di.IPAddress())
				assert.Equal(t, tt.ua, di.UserAgent())
			}
		})
	}
}

func TestDeviceIdentity_Fingerprint(t *testing.T) {
	di := ReconstituteDeviceIdentity("1.2.3.4", "Linux", "Chrome", "Desktop", "en-US", "UA-string", false)
	fp := di.Fingerprint()

	raw := fmt.Sprintf("%s|%s|%s|%s", "UA-string", "Linux", "Chrome", "0")
	hash := sha256.Sum256([]byte(raw))
	expected := hex.EncodeToString(hash[:])

	assert.Len(t, fp.String(), 64)
	assert.Equal(t, expected, fp.String())
}

func TestDeviceIdentity_DisplayName(t *testing.T) {
	t.Run("mobile_with_model", func(t *testing.T) {
		di := ReconstituteDeviceIdentity("1.2.3.4", "iOS", "Safari", "iPhone 15", "en", "ua", true)
		assert.Equal(t, "iPhone 15 (Safari)", di.DisplayName())
	})

	t.Run("mobile_generic_model", func(t *testing.T) {
		di := ReconstituteDeviceIdentity("1.2.3.4", "Android", "Chrome", "Generic", "en", "ua", true)
		assert.Equal(t, "Chrome on Android", di.DisplayName())
	})

	t.Run("mobile_empty_model", func(t *testing.T) {
		di := ReconstituteDeviceIdentity("1.2.3.4", "Android", "Chrome", "", "en", "ua", true)
		assert.Equal(t, "Chrome on Android", di.DisplayName())
	})

	t.Run("desktop", func(t *testing.T) {
		di := ReconstituteDeviceIdentity("1.2.3.4", "Windows", "Firefox", "Desktop", "en", "ua", false)
		assert.Equal(t, "Firefox on Windows", di.DisplayName())
	})
}

func TestNewDeviceFingerprint(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		fp, err := NewDeviceFingerprint("ua|1.2.3.4|en")
		require.NoError(t, err)
		assert.Equal(t, "ua|1.2.3.4|en", fp.String())
	})

	t.Run("empty", func(t *testing.T) {
		_, err := NewDeviceFingerprint("")
		assert.ErrorIs(t, err, ErrDeviceFingerprintRequired)
	})
}

func TestDeviceFingerprint_Equal(t *testing.T) {
	a := NewDeviceFingerprintFromIdentity("ua", "Linux", "Chrome", false)
	b := NewDeviceFingerprintFromIdentity("ua", "Linux", "Chrome", false)
	c := NewDeviceFingerprintFromIdentity("different", "Linux", "Chrome", false)
	assert.True(t, a.Equal(b))
	assert.False(t, a.Equal(c))
}
