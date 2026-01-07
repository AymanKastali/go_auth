package valueobjects

type JWTToken struct {
	value string
}

func NewJWTToken(signedToken string) JWTToken {
	return JWTToken{value: signedToken}
}

func (vo JWTToken) Value() string {
	return vo.value
}
