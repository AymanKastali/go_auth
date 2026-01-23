package valueobjects

import (
	"go_auth/internal/core/domain/derr"
	"strings"
)

type HashedPassword struct{ v string }

func NewHashedPassword(v string) (HashedPassword, error) {
	trimmed := strings.TrimSpace(v)

	if trimmed == "" {
		return HashedPassword{}, derr.NewErrTokenHashRequired()
	}
	return HashedPassword{v: trimmed}, nil
}

func ReconstituteHashedPassword(v string) HashedPassword { return HashedPassword{v: v} }

func (vo HashedPassword) String() string                  { return vo.v }
func (vo HashedPassword) IsEmpty() bool                   { return vo.v == "" }
func (vo HashedPassword) Equal(other HashedPassword) bool { return vo.v == other.v }
