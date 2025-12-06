package valueobjects

type PasswordHash struct {
	value string
}

func NewPasswordHash(value string) PasswordHash {
	return PasswordHash{value: value}
}

func (p PasswordHash) Value() string {
	return p.value
}
