package services

import (
	"golang.org/x/crypto/bcrypt"
)

type BcryptPasswordService struct {
	cost int
}

func NewBcryptPasswordService(cost int) *BcryptPasswordService {
	return &BcryptPasswordService{cost: cost}
}

func (b *BcryptPasswordService) Hash(raw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(raw), b.cost)
	return string(h), err
}

func (b *BcryptPasswordService) Compare(raw, hashed string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(raw))
	return err == nil
}
