package valueobjects

import (
	"go_auth/internal/core/domain/derr"
	"strings"
)

const (
	MinPasswordLength    = 10
	PasswordRequirements = "uppercase, lowercase, numbers, and symbols"
)

type RawPassword struct{ value string }

func NewRawPassword(value string) (RawPassword, error) {
	trimmed := strings.TrimSpace(value)

	if trimmed == "" {
		return RawPassword{}, derr.NewErrPasswordRequired()
	}
	return RawPassword{value: value}, nil
}

func (vo RawPassword) Value() string { return vo.value }
