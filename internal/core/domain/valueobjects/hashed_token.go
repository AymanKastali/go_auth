package valueobjects

type HashedToken struct{ value string }

func ReconstituteHashedToken(value string) HashedToken {
	return HashedToken{value: value}
}

func (vo HashedToken) Value() string                { return vo.value }
func (vo HashedToken) IsEmpty() bool                { return vo.value == "" }
func (vo HashedToken) Equal(other HashedToken) bool { return vo.value == other.value }
