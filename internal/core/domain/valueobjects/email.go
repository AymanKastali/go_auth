package valueobjects

import (
	"go_auth/internal/core/domain/derr"
	"regexp"
	"strings"
)

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

type Email struct{ v string }

func NewEmail(email string) (Email, error) {
	trimmed := strings.TrimSpace(email)

	if trimmed == "" {
		return Email{}, derr.NewErrEmailRequired()
	}

	if !emailRegex.MatchString(trimmed) {
		return Email{}, derr.NewErrInvalidEmailFormat()
	}

	return Email{v: trimmed}, nil
}

func ReconstituteEmail(email string) Email {
	return Email{v: email}
}

func (vo Email) String() string         { return vo.v }
func (vo Email) IsEmpty() bool          { return vo.v == "" }
func (vo Email) Equal(other Email) bool { return vo.v == other.v }
