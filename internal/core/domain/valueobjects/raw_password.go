package valueobjects

import (
	"go_auth/internal/core/domain/derr"
	"strings"
	"unicode"
)

const (
	MinPasswordLength    = 10
	PasswordRequirements = "uppercase, lowercase, numbers, and symbols"
)

type RawPassword struct{ value string }

func NewRawPassword(value string) (RawPassword, error) {
	trimmed := strings.TrimSpace(value)

	// 1. Dynamic Length Check
	if len(trimmed) < MinPasswordLength {
		return RawPassword{}, derr.ErrPasswordTooShort(MinPasswordLength)
	}

	var hasUpper, hasLower, hasNumber, hasSpecial bool
	for _, char := range trimmed {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	// 2. Dynamic Complexity Check
	if !hasUpper || !hasLower || !hasNumber || !hasSpecial {
		return RawPassword{}, derr.ErrPasswordTooWeak(PasswordRequirements)
	}

	return RawPassword{value: trimmed}, nil
}

func (vo RawPassword) Value() string { return vo.value }
