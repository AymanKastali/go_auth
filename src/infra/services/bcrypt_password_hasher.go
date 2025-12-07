package services

import (
	"golang.org/x/crypto/bcrypt"

	portservices "go_auth/src/domain/ports/services"
	valueobjects "go_auth/src/domain/value_objects"
)

type BcryptPasswordHasher struct {
	cost int
}

func NewBcryptPasswordHasher(cost int) portservices.PasswordHasher {
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}
	return &BcryptPasswordHasher{cost: cost}
}

func (b *BcryptPasswordHasher) Hash(plain string) (valueobjects.PasswordHash, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(plain), b.cost)
	if err != nil {
		return valueobjects.PasswordHash{}, err
	}

	return valueobjects.NewPasswordHash(string(bytes)), nil
}

func (b *BcryptPasswordHasher) Verify(
	plain string,
	hash valueobjects.PasswordHash,
) bool {
	err := bcrypt.CompareHashAndPassword(
		[]byte(hash.Value()),
		[]byte(plain),
	)

	return err == nil
}
