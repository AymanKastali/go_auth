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

func (h *hmacHasher) Hash(raw string) (valueobjects.HashedToken, error) {
	mac := hmac.New(sha256.New, h.secret)
	mac.Write([]byte(raw))
	return valueobjects.ReconstituteHashedToken(hex.EncodeToString(mac.Sum(nil))), nil
}

func (h *hmacHasher) Compare(raw string, hash valueobjects.HashedToken) bool {
	expected, _ := h.Hash(raw)
	return hmac.Equal([]byte(hash.Value()), []byte(expected.Value()))
}
