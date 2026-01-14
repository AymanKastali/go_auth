package valueobjects

import (
	"go_auth/internal/core/domain/derr"
	"strings"
)

type TokenID struct {
	value string
}

func NewTokenID(value string) (TokenID, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return TokenID{}, derr.ErrTokenIDRequired()
	}
	return TokenID{value: trimmed}, nil
}

func (vo TokenID) Value() string            { return vo.value }
func (vo TokenID) IsEmpty() bool            { return vo.value == "" }
func (vo TokenID) Equal(other TokenID) bool { return vo.value == other.value }
