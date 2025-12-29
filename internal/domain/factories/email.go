package factories

import (
	"errors"
	"go_auth/internal/domain/valueobjects"
	"regexp"
)

type EmailFactoryInterface interface {
	New(email string) (valueobjects.Email, error)
}

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

type EmailFactory struct{}

func (f *EmailFactory) New(email string) (valueobjects.Email, error) {
	if !emailRegex.MatchString(email) {
		return valueobjects.Email{}, errors.New("invalid email format")
	}
	return valueobjects.Email{Value: email}, nil
}
