package password

import (
	"golang.org/x/crypto/bcrypt"
)

type BcryptHashedPassworder struct {
	cost int
}

func NewBcryptHashedPassworder(cost int) *BcryptHashedPassworder {
	return &BcryptHashedPassworder{cost: cost}
}

func (b *BcryptHashedPassworder) Hash(raw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(raw), b.cost)
	return string(h), err
}

func (b *BcryptHashedPassworder) Compare(raw, hashed string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(raw))
	return err == nil
}
