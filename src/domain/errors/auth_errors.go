package errors

import "errors"

var (
	ErrInvalidCredentials     = errors.New("invalid credentials")
	ErrAccountDisabled        = errors.New("account disabled")
	ErrSessionExpired         = errors.New("session expired")
	ErrEmailAlreadyRegistered = errors.New("email is already registered")
	ErrUserNotFound           = errors.New("user not found")
	ErrSessionNotFound        = errors.New("session not found")
)
