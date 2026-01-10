package valueobjects

import (
	"go_auth/internal/core/domain/derr"
)

type TokenID struct {
	value string
}

func NewTokenID(value string) (TokenID, error) {
	if value == "" {
		return TokenID{}, derr.NewInvalidValueErr("TokenID")
	}

	return TokenID{value: value}, nil
}

func (vo TokenID) Value() string            { return vo.value }
func (vo TokenID) IsEmpty() bool            { return vo.value == "" }
func (vo TokenID) Equal(other TokenID) bool { return vo.value == other.value }
