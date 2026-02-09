package outbound

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"go_auth/internal/domain"
)

// Token Service
type tokenService struct{}

func NewTokenService() domain.ITokenService {
	return &tokenService{}
}

func (s *tokenService) Generate() (domain.RawToken, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return domain.ZeroRawToken, domain.ErrInternal
	}
	return domain.NewRawToken(hex.EncodeToString(b))
}

// --- Session Context ---

func (s *tokenService) HashSessionToken(raw domain.RawToken) (domain.HashedToken, error) {
	hash := s.computeHash(raw)
	return domain.NewHashedToken(hash)
}

func (s *tokenService) CompareSession(raw domain.RawToken, hashed domain.HashedToken) bool {
	actualHash := s.computeHash(raw)
	return s.secureCompare(actualHash, hashed.String())
}

// --- Recovery Context ---

func (s *tokenService) HashRecoveryToken(raw domain.RawToken) (domain.RecoveryTokenHash, error) {
	hash := s.computeHash(raw)
	// Here we use the specific Recovery Value Object
	return domain.NewRecoveryTokenHash(hash)
}

func (s *tokenService) CompareRecovery(raw domain.RawToken, hashed domain.RecoveryTokenHash) bool {
	actualHash := s.computeHash(raw)
	return s.secureCompare(actualHash, hashed.String())
}

// --- Activation Context ---

func (s *tokenService) HashActivationToken(raw domain.RawToken) (domain.ActivationTokenHash, error) {
	hash := s.computeHash(raw)
	return domain.NewActivationTokenHash(hash)
}

func (s *tokenService) CompareActivation(raw domain.RawToken, hashed domain.ActivationTokenHash) bool {
	actualHash := s.computeHash(raw)
	return s.secureCompare(actualHash, hashed.String())
}

// --- Private Helpers (DRY the technical implementation) ---

func (s *tokenService) computeHash(raw domain.RawToken) string {
	hash := sha256.Sum256([]byte(raw.String()))
	return hex.EncodeToString(hash[:])
}

func (s *tokenService) secureCompare(actual, expected string) bool {
	return subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) == 1
}
