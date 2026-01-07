package jwt

import "errors"

var (
	ErrUnexpectedMethod = errors.New("unexpected signing method")
	ErrInvalidToken     = errors.New("invalid token")
	ErrTypeMismatch     = errors.New("token type mismatch")
)
