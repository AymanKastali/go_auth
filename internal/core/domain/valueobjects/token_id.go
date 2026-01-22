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
		return TokenID{}, derr.NewErrRefreshTokenIDRequired()
	}
	return TokenID{value: trimmed}, nil
}

func ReconstituteTokenID(s string) TokenID { return TokenID{value: s} }

func (vo TokenID) Value() string            { return vo.value }
func (vo TokenID) IsEmpty() bool            { return vo.value == "" }
func (vo TokenID) Equal(other TokenID) bool { return vo.value == other.value }
