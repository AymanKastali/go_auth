package valueobjects

import (
	"errors"
	"go_auth/internal/core/domain/domainerr"
	"regexp"
)

const newEmailOp = "Email.NewEmail"

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

type Email struct {
	value string
}

func NewEmail(email string) (Email, error) {
	if !emailRegex.MatchString(email) {
		return Email{}, domainerr.NewDomainInvalidValueError(
			"email",
			newEmailOp,
			errors.New("invalid email format"),
		)
	}
	return Email{value: email}, nil
}

func (vo Email) Value() string {
	return vo.value
}

func (vo Email) Equal(other Email) bool {
	return vo.value == other.value
}

func (vo Email) String() string {
	return vo.value
}
