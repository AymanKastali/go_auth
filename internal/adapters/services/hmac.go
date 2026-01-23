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

func (h *hmacHasher) Hash(raw valueobjects.SessionRenewalRawTokenSecret) (valueobjects.SessionRenewalHashedToken, error) {
	mac := hmac.New(sha256.New, h.secret)
	mac.Write([]byte(raw.String()))
	hashedStr := hex.EncodeToString(mac.Sum(nil))

	return valueobjects.NewSessionRenewalHashedToken(hashedStr)
}

func (h *hmacHasher) Compare(raw valueobjects.SessionRenewalRawTokenSecret, hash valueobjects.SessionRenewalHashedToken) (bool, error) {
	stored, err := hex.DecodeString(hash.String())
	if err != nil {
		return false, derr.NewErrTokenHashRequired()
	}

	mac := hmac.New(sha256.New, h.secret)
	mac.Write([]byte(raw.String()))
	expected := mac.Sum(nil)

	return hmac.Equal(stored, expected), nil
}
