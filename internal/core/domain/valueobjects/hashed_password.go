package valueobjects

type HashedPassword struct{ value string }

func ReconstituteHashedPassword(value string) HashedPassword {
	return HashedPassword{value: value}
}

func (vo HashedPassword) Value() string                   { return vo.value }
func (vo HashedPassword) IsEmpty() bool                   { return vo.value == "" }
func (vo HashedPassword) Equal(other HashedPassword) bool { return vo.value == other.value }
