package valueobjects

import (
	"go_auth/internal/core/domain/derr"
	"strings"
)

type HashedToken struct{ v string }

func NewHashedToken(v string) (HashedToken, error) {
	trimmed := strings.TrimSpace(v)

	if trimmed == "" {
		return HashedToken{}, derr.NewErrTokenHashRequired()
	}
	return HashedToken{v: trimmed}, nil
}

func ReconstituteHashedToken(v string) HashedToken { return HashedToken{v: v} }

func (vo HashedToken) String() string               { return vo.v }
func (vo HashedToken) IsEmpty() bool                { return vo.v == "" }
func (vo HashedToken) Equal(other HashedToken) bool { return vo.v == other.v }
