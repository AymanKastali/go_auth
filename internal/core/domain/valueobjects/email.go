package valueobjects

import (
	"go_auth/internal/core/domain/domainerr"
	"regexp"
)

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

type Email struct {
	value string
}

// NewEmail validates and creates a new Email value object
func NewEmail(email string) (Email, error) {
	if email == "" {
		return Email{}, domainerr.NewRequired("email")
	}

	if !emailRegex.MatchString(email) {
		// Aligned with V2 factory: NewInvalidValue(attr, msg string)
		return Email{}, domainerr.NewInvalidValue("email", "invalid email format")
	}

	return Email{value: email}, nil
}

// Value returns the raw string value
func (vo Email) Value() string {
	return vo.value
}

// Equal compares two Email objects for equality
func (vo Email) Equal(other Email) bool {
	return vo.value == other.value
}

// String implements the Stringer interface
func (vo Email) String() string {
	return vo.value
}
