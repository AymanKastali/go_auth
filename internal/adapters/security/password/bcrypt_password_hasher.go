package password

import (
	"golang.org/x/crypto/bcrypt"
)

type BcryptPasswordHasher struct {
	cost int
}

func NewBcryptPasswordHasher(cost int) *BcryptPasswordHasher {
	return &BcryptPasswordHasher{cost: cost}
}

func (b *BcryptPasswordHasher) Hash(raw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(raw), b.cost)
	return string(h), err
}

func (b *BcryptPasswordHasher) Compare(raw, hashed string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(raw))
	return err == nil
}
