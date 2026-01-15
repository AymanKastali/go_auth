package services

import (
	"golang.org/x/crypto/bcrypt"
)

type bcryptHashedPassword struct {
	cost int
}

func NewBcryptHashedPassword(cost int) *bcryptHashedPassword {
	return &bcryptHashedPassword{cost: cost}
}

func (b *bcryptHashedPassword) Hash(raw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(raw), b.cost)
	return string(h), err
}

func (b *bcryptHashedPassword) Compare(raw, hashed string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(raw))
	return err == nil
}

func (b *bcryptHashedPassword) IsValidHash(hashed string) bool {
	_, err := bcrypt.Cost([]byte(hashed))
	return err == nil
}
