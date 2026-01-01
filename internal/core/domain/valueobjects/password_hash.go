package valueobjects

type HashedPassword struct {
	value string
}

func NewHashedPassword(value string) HashedPassword {
	return HashedPassword{value: value}
}

func (vo HashedPassword) Value() string {
	return vo.value
}

func (vo HashedPassword) String() string {
	return vo.value
}
