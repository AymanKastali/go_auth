package services

import (
	"go_auth/internal/core/domain/derr"
	"go_auth/internal/core/domain/valueobjects"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

type bcryptHasher struct {
	cost int
}

func NewBcryptHasher(cost int) *bcryptHasher {
	return &bcryptHasher{cost: cost}
}

func (h *bcryptHasher) Hash(raw valueobjects.RawPassword) (valueobjects.HashedPassword, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(raw.Value()), h.cost)
	if err != nil {
		return valueobjects.HashedPassword{}, err
	}
	return valueobjects.ReconstituteHashedPassword(string(bytes)), nil
}

func (h *bcryptHasher) Compare(plain string, hashed valueobjects.HashedPassword) error {
	err := bcrypt.CompareHashAndPassword([]byte(hashed.Value()), []byte(plain))
	if err != nil {
		// Here you would return your specific Domain Error
		return derr.NewErrPasswordMismatch()
	}
	return nil
}

func (h *bcryptHasher) IsValidFormat(hashed string) bool {
	// 1. Bcrypt hashes are exactly 60 characters
	if len(hashed) != 60 {
		return false
	}

	// 2. Check for standard Bcrypt prefixes
	if !strings.HasPrefix(hashed, "$2a$") &&
		!strings.HasPrefix(hashed, "$2b$") &&
		!strings.HasPrefix(hashed, "$2y$") {
		return false
	}

	// 3. Verify structure via the library
	_, err := bcrypt.Cost([]byte(hashed))
	return err == nil
}
