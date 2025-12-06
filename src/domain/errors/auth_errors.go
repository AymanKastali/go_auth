// domain/auth/errors/auth_errors.go
package errors

import "errors"

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrTokenRevoked       = errors.New("token revoked")
)
