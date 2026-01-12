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
		return Token{}, derr.NewValidation.RequiredToken()
	}
	return Token{value: trimmed}, nil
}

func (vo Token) Value() string { return vo.value }
func (vo Token) IsEmpty() bool { return vo.value == "" }
