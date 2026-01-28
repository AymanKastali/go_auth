package domain

import (
	"regexp"
	"time"
)

var (
	upperRegex   = regexp.MustCompile(`[A-Z]`)
	numberRegex  = regexp.MustCompile(`[0-9]`)
	specialRegex = regexp.MustCompile(`[!@#\$%\^&\*]`)
)

// Password Policy
type passwordPolicy struct {
	minLength      uint8
	maxLength      uint8
	requireUpper   bool
	requireNumber  bool
	requireSpecial bool
}

func NewPasswordPolicy(
	min uint8,
	max uint8,
	upper bool,
	num bool,
	special bool,
) IPasswordPolicy {
	return &passwordPolicy{
		minLength:      min,
		maxLength:      max,
		requireUpper:   upper,
		requireNumber:  num,
		requireSpecial: special,
	}
}

func (p *passwordPolicy) Validate(password RawPassword) error {
	pwdStr := password.String()
	length := len(pwdStr)

	// 1. Length Checks
	if length < int(p.minLength) {
		return NewPasswordTooShortError(p.minLength)
	}
	if length > int(p.maxLength) {
		return NewPasswordTooLongError(p.maxLength)
	}

	// 2. Complexity Checks using pre-compiled regex
	if p.requireUpper && !upperRegex.MatchString(pwdStr) {
		return NewPasswordMissingUppercaseError()
	}
	if p.requireNumber && !numberRegex.MatchString(pwdStr) {
		return NewPasswordMissingNumberError()
	}
	if p.requireSpecial && !specialRegex.MatchString(pwdStr) {
		return NewPasswordMissingSpecialCharError()
	}

	return nil
}

// Session Policy
type sessionPolicy struct {
	lifetime  time.Duration
	maxActive uint8
}

func NewSessionPolicy(
	lifetime time.Duration,
	maxActive uint8,
) ISessionPolicy {
	return &sessionPolicy{
		lifetime:  lifetime,
		maxActive: maxActive,
	}
}

func (p *sessionPolicy) GetSessionLifetime() time.Duration {
	return p.lifetime
}

func (p *sessionPolicy) GetMaxActiveSessions() int {
	return int(p.maxActive)
}

// Access Policy
type accessPolicy struct {
	lifetime time.Duration
}

func NewAccessPolicy(
	lifetime time.Duration,
) IAccessPolicy {
	return &accessPolicy{
		lifetime: lifetime,
	}
}

func (p *accessPolicy) GetAccessLifetime() time.Duration {
	return p.lifetime
}
