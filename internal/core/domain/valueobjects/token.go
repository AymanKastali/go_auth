package valueobjects

import "go_auth/internal/core/domain/derr"

type Token struct {
	value string
}

func NewToken(value string) (Token, error) {
	if value == "" {
		return Token{}, derr.NewRequiredErr("token")
	}
	return Token{value: value}, nil
}

func (vo Token) Value() string { return vo.value }
func (vo Token) IsEmpty() bool { return vo.value == "" }
