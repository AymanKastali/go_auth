package outbound

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"go_auth/internal/domain"
)

// Token Service
type tokenService struct {
	tokenLength int
}

func NewTokenService(tokenLength int) domain.ITokenService {
	return &tokenService{tokenLength: tokenLength}
}

func (s *tokenService) Generate() (string, error) {
	b := make([]byte, s.tokenLength)
	if _, err := rand.Read(b); err != nil {
		return "", domain.ErrInternal
	}
	return hex.EncodeToString(b), nil
}

// --- Session Context ---

func (s *tokenService) HashSessionToken(raw string) (domain.HashedToken, error) {
	hash := s.computeHash(raw)
	return domain.NewHashedToken(hash)
}

func (s *tokenService) CompareSession(raw string, hashed domain.HashedToken) bool {
	actualHash := s.computeHash(raw)
	return s.secureCompare(actualHash, hashed.String())
}

// --- Recovery Context ---

func (s *tokenService) HashRecoveryToken(raw string) (domain.RecoveryTokenHash, error) {
	hash := s.computeHash(raw)
	// Here we use the specific Recovery Value Object
	return domain.NewRecoveryTokenHash(hash)
}

func (s *tokenService) CompareRecovery(raw string, hashed domain.RecoveryTokenHash) bool {
	actualHash := s.computeHash(raw)
	return s.secureCompare(actualHash, hashed.String())
}

// --- Activation Context ---

func (s *tokenService) HashActivationToken(raw string) (domain.ActivationTokenHash, error) {
	hash := s.computeHash(raw)
	return domain.NewActivationTokenHash(hash)
}

func (s *tokenService) CompareActivation(raw string, hashed domain.ActivationTokenHash) bool {
	actualHash := s.computeHash(raw)
	return s.secureCompare(actualHash, hashed.String())
}

// --- Private Helpers (DRY the technical implementation) ---

func (s *tokenService) computeHash(raw string) string {
	hash := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(hash[:])
}

func (s *tokenService) secureCompare(actual, expected string) bool {
	return subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) == 1
}
