package services

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"go_auth/internal/core/domain/derr"
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
	hashedStr := hex.EncodeToString(mac.Sum(nil))

	hashedVO, err := valueobjects.NewHashedToken(hashedStr)
	if err != nil {
		return valueobjects.HashedToken{}, derr.NewErrTokenHashRequired()
	}
	return hashedVO, nil
}

func (h *hmacHasher) Compare(raw string, hash valueobjects.HashedToken) (bool, error) {
	stored, err := hex.DecodeString(hash.Value())
	if err != nil {
		return false, derr.NewErrTokenHashRequired()
	}

	mac := hmac.New(sha256.New, h.secret)
	mac.Write([]byte(raw))
	expected := mac.Sum(nil)

	return hmac.Equal(stored, expected), nil
}
