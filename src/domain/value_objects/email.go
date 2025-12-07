package valueobjects

import (
	"errors"
	"regexp"
)

type Email struct {
	value string
}

func NewEmail(value string) (Email, error) {
	r := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+$`)
	if !r.MatchString(value) {
		return Email{}, errors.New("invalid email format")
	}
	return Email{value: value}, nil
}

func (e Email) Value() string {
	return e.value
}
