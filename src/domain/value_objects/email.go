package valueobjects

import (
	"errors"
	"regexp"
)

type Email struct {
	value string
}

func NewEmail(value string) (Email, error) {
	re := regexp.MustCompile(`^[^@]+@[^@]+\.[^@]+$`)
	if !re.MatchString(value) {
		return Email{}, errors.New("invalid email")
	}
	return Email{value: value}, nil
}

func (e Email) Value() string {
	return e.value
}
