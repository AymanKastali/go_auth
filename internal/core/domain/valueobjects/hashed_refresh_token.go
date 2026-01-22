package valueobjects

import (
	"go_auth/internal/core/domain/derr"
	"strings"
)

type HashedToken struct {
	value string
}

func NewHashedToken(value string) (HashedToken, error) {
	trimmed := strings.TrimSpace(value)

	if trimmed == "" {
		return HashedToken{}, derr.NewErrTokenHashRequired()
	}
	return HashedToken{value: trimmed}, nil
}

func ReconstituteHashedToken(value string) HashedToken { return HashedToken{value: value} }

func (vo HashedToken) Value() string                { return vo.value }
func (vo HashedToken) IsEmpty() bool                { return vo.value == "" }
func (vo HashedToken) Equal(other HashedToken) bool { return vo.value == other.value }
