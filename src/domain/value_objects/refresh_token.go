package valueobjects

type RefreshToken struct {
	value string
}

func NewRefreshToken(value string) RefreshToken {
	return RefreshToken{value: value}
}

func (t RefreshToken) Value() string {
	return t.value
}
