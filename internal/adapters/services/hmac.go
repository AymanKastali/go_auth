package services

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"go_auth/internal/core/domain/valueobjects"
)

type hmacHasher struct {
	secret []byte
}

func NewHMACHasher(secret []byte) *hmacHasher {
	return &hmacHasher{secret: secret}
}

func (h *hmacHasher) Hash(raw string) valueobjects.HashedToken {
	mac := hmac.New(sha256.New, h.secret)
	mac.Write([]byte(raw))

	return valueobjects.ReconstituteHashedToken(
		hex.EncodeToString(mac.Sum(nil)),
	)
}

func (h *hmacHasher) Compare(raw string, hash valueobjects.HashedToken) bool {
	mac := hmac.New(sha256.New, h.secret)
	mac.Write([]byte(raw))
	expected := mac.Sum(nil)
	stored, err := hex.DecodeString(hash.Value())
	if err != nil {
		return false
	}
	return hmac.Equal(stored, expected)
}
