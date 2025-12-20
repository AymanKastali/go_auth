package factories

import "go_auth/src/domain/value_objects"

type PasswordHashFactory struct{}

func (f *PasswordHashFactory) New(value string) value_objects.PasswordHash {
	return value_objects.PasswordHash{Value: value}
}
