package services

import (
	"crypto/sha256"
	"encoding/hex"
	"go_auth/internal/core/domain/valueobjects"
)

type DeviceHasher struct{ secret string }

func NewDeviceHasher(secret string) *DeviceHasher {
	return &DeviceHasher{secret: secret}
}

func (s *DeviceHasher) Hash(t valueobjects.DeviceFingerprintTraits) (valueobjects.DeviceFingerprint, error) {
	// 1. Create a new hasher instance
	h := sha256.New()

	// 2. Write the raw device data
	h.Write(t.Bytes())

	// 3. Write the secret (The Pepper)
	// This ensures that even identical hardware produces a different hash on different apps
	h.Write([]byte(s.secret))

	// 4. Sum it up and return the Value Object
	hashStr := hex.EncodeToString(h.Sum(nil))
	return valueobjects.NewDeviceFingerprint(hashStr)
}
