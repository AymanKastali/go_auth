package valueobjects

import (
	"go_auth/internal/core/domain/derr"
	"strings"
)

type RawRefreshToken struct{ value string }

func NewRawRefreshToken(value string) (RawRefreshToken, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return RawRefreshToken{}, derr.NewErrTokenRequired()
	}
	return RawRefreshToken{value: trimmed}, nil
}

func (vo RawRefreshToken) Value() string { return vo.value }
