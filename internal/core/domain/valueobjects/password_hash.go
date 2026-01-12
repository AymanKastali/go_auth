package valueobjects

import (
	"go_auth/internal/core/domain/derr"
	"strings"
)

type HashedPassword struct {
	value string
}

func NewHashedPassword(value string) (HashedPassword, error) {
	trimmed := strings.TrimSpace(value)

	if trimmed == "" {
		return HashedPassword{}, derr.NewValidation.RequiredPassword()
	}

	return HashedPassword{value: trimmed}, nil
}

func (vo HashedPassword) Value() string                   { return vo.value }
func (vo HashedPassword) IsEmpty() bool                   { return vo.value == "" }
func (vo HashedPassword) Equal(other HashedPassword) bool { return vo.value == other.value }
