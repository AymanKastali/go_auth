package valueobjects

import "go_auth/internal/core/domain/derr"

type HashedToken struct {
	value string
}

func NewHashedToken(value string) (HashedToken, error) {
	if value == "" {
		return HashedToken{}, derr.NewErrTokenHashRequired()
	}
	return HashedToken{value: value}, nil
}

func ReconstituteHashedToken(value string) HashedToken {
	return HashedToken{value: value}
}

func (vo HashedToken) Value() string                { return vo.value }
func (vo HashedToken) IsEmpty() bool                { return vo.value == "" }
func (vo HashedToken) Equal(other HashedToken) bool { return vo.value == other.value }
