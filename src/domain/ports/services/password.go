package services

import valueobjects "go_auth/src/domain/value_objects"

type PasswordHasher interface {
	Hash(plain string) (valueobjects.PasswordHash, error)
	Verify(plain string, hash valueobjects.PasswordHash) bool
}
