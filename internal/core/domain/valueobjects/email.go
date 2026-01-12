package valueobjects

import (
	"go_auth/internal/core/domain/derr"
	"regexp"
	"strings"
)

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

type Email struct {
	value string
}

func NewEmail(email string) (Email, error) {
	trimmed := strings.TrimSpace(email)

	if trimmed == "" {
		return Email{}, derr.NewValidation.RequiredEmail()
	}

	if !emailRegex.MatchString(trimmed) {
		return Email{}, derr.NewValidation.InvalidEmail()
	}

	return Email{value: trimmed}, nil
}

func (vo Email) Value() string          { return vo.value }
func (vo Email) IsEmpty() bool          { return vo.value == "" }
func (vo Email) Equal(other Email) bool { return vo.value == other.value }
