package factories

import "go_auth/internal/domain/valueobjects"

type PasswordHashFactory struct{}

func (f *PasswordHashFactory) New(value string) valueobjects.PasswordHash {
	return valueobjects.PasswordHash{Value: value}
}
