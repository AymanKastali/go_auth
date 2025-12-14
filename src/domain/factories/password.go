package factories

import (
	valueobjects "go_auth/src/domain/value_objects"
)

type PasswordHashFactory struct{}

func (f *PasswordHashFactory) New(value string) valueobjects.PasswordHash {
	return valueobjects.PasswordHash{Value: value}
}
