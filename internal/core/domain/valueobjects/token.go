package valueobjects

import (
	"go_auth/internal/core/domain/derr"
	"strings"
)

type Token struct {
	value string
}

func NewToken(value string) (Token, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return Token{}, derr.ErrTokenRequired()
	}
	return Token{value: trimmed}, nil
}

func ReconstituteToken(value string) Token {
	return Token{value: value}
}

func (vo Token) Value() string { return vo.value }
func (vo Token) IsEmpty() bool { return vo.value == "" }
