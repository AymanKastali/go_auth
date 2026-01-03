package apperr

import (
	"errors"
	"go_auth/internal/core/domain/domainerr"
)

// Application-level Sentinel Errors
// These describe "Process" failures rather than "Business Rule" failures.
var (
	ErrInternal           = errors.New("internal server error")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUnauthorized       = errors.New("unauthorized access")
	ErrNotFound           = errors.New("resource not found")
	ErrConflict           = errors.New("resource already exists")
	ErrDeviceNotFound     = errors.New("device not found")
	ErrUserInactive       = errors.New("user account is inactive")
	ErrTokenExpired       = errors.New("session has expired")
)

// MapDomain categorizes a domain error into an application context.
// It is the "Firewall" between the inner Domain and the Application use cases.
func MapDomain(err error) error {
	if err == nil {
		return nil
	}

	// If it's already a DomainError interface, we return it as is.
	// This allows the Adapters layer to use errors.As() to find the Code() and Attr().
	var dErr domainerr.DomainError
	if errors.As(err, &dErr) {
		switch dErr.Code() {
		case domainerr.CodeRequired, domainerr.CodeInvalidValue, domainerr.CodeRuleViolation:
			// These are "Safe" errors to pass to the user because they
			// describe business constraints, not technical failures.
			return err
		case domainerr.CodeInternal:
			return ErrInternal
		default:
			return ErrInternal
		}
	}

	// If it's not a DomainError (e.g., a raw string error or fmt.Errorf),
	// it's considered an untrusted internal error.
	return ErrInternal
}
