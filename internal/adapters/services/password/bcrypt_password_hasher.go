package password

import (
	"golang.org/x/crypto/bcrypt"
)

type BcryptHashedPassword struct {
	cost int
}

func NewBcryptHashedPassword(cost int) *BcryptHashedPassword {
	return &BcryptHashedPassword{cost: cost}
}

func (b *BcryptHashedPassword) Hash(raw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(raw), b.cost)
	return string(h), err
}

func (b *BcryptHashedPassword) Compare(raw, hashed string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(raw))
	return err == nil
}
