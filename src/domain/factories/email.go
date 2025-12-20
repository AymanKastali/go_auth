package factories

import (
	"errors"
	value_objects "go_auth/src/domain/value_objects"
	"regexp"
)

type EmailFactoryInterface interface {
	New(email string) (value_objects.Email, error)
}

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

type EmailFactory struct{}

func (f *EmailFactory) New(email string) (value_objects.Email, error) {
	if !emailRegex.MatchString(email) {
		return value_objects.Email{}, errors.New("invalid email format")
	}
	return value_objects.Email{Value: email}, nil
}
