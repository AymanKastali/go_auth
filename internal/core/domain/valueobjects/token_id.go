package valueobjects

import (
	"go_auth/internal/core/domain/derr"
	"strings"
)

type TokenID struct{ v string }

func NewTokenID(v string) (TokenID, error) {
	trimmed := strings.TrimSpace(v)
	if trimmed == "" {
		return TokenID{}, derr.NewErrRefreshTokenIDRequired()
	}
	return TokenID{v: trimmed}, nil
}

func ReconstituteTokenID(s string) TokenID { return TokenID{v: s} }

func (vo TokenID) String() string           { return vo.v }
func (vo TokenID) IsEmpty() bool            { return vo.v == "" }
func (vo TokenID) Equal(other TokenID) bool { return vo.v == other.v }
