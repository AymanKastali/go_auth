package errors

import "errors"

var (
	// Seeder / environment errors
	ErrInvalidEnv = errors.New("ADMIN_EMAIL or ADMIN_PASSWORD environment variables are not set")

	// User registration / validation errors
	ErrInvalidEmail           = errors.New("invalid email address")
	ErrEmailAlreadyRegistered = errors.New("email is already registered")

	// Generic internal / unexpected errors
	ErrInternal = errors.New("internal server error")
)
