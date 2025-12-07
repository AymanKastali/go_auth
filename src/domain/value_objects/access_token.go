package valueobjects

type AccessToken struct {
	value string
}

func NewAccessToken(value string) AccessToken {
	return AccessToken{value: value}
}

func (t AccessToken) Value() string {
	return t.value
}
