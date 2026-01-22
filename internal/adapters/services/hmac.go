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

func (h *hmacHasher) Hash(raw valueobjects.RefreshTokenSecret) (valueobjects.HashedToken, error) {
	mac := hmac.New(sha256.New, h.secret)
	mac.Write([]byte(raw.String()))
	hashedStr := hex.EncodeToString(mac.Sum(nil))

	return valueobjects.NewHashedToken(hashedStr)
}

func (h *hmacHasher) Compare(raw valueobjects.RefreshTokenSecret, hash valueobjects.HashedToken) (bool, error) {
	stored, err := hex.DecodeString(hash.String())
	if err != nil {
		return false, derr.NewErrTokenHashRequired()
	}

	mac := hmac.New(sha256.New, h.secret)
	mac.Write([]byte(raw.String()))
	expected := mac.Sum(nil)

	return hmac.Equal(stored, expected), nil
}
