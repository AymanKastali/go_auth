package policies

import (
	"go_auth/internal/core/domain/derr"
	"go_auth/internal/core/domain/valueobjects"
	"regexp"
)

type PasswordPolicy struct {
	MinLength      uint8
	MaxLength      uint8
	RequireUpper   bool
	RequireNumber  bool
	RequireSpecial bool
}

func NewDefaultPasswordPolicy() *PasswordPolicy {
	return &PasswordPolicy{
		MinLength:      8,
		MaxLength:      64,
		RequireUpper:   true,
		RequireNumber:  true,
		RequireSpecial: true,
	}
}

func (p *PasswordPolicy) Validate(password valueobjects.RawPassword) error {
	pwdStr := password.Value()

	if len(pwdStr) < int(p.MinLength) {
		return derr.NewErrPasswordTooShort(p.MinLength)
	}
	if len(pwdStr) > int(p.MaxLength) {
		return derr.NewErrPasswordTooLong(p.MaxLength)
	}
	if p.RequireUpper && !regexp.MustCompile(`[A-Z]`).MatchString(pwdStr) {
		return derr.NewErrPasswordMissingUppercase()
	}
	if p.RequireNumber && !regexp.MustCompile(`[0-9]`).MatchString(pwdStr) {
		return derr.NewErrPasswordMissingNumber()
	}
	if p.RequireSpecial && !regexp.MustCompile(`[!@#\$%\^&\*]`).MatchString(pwdStr) {
		return derr.NewErrPasswordMissingSpecialChar()
	}

	return nil
}
