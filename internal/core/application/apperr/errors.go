package apperr

import (
	"fmt"
	"go_auth/internal/core/domain/derr"
)

type Type string

const (
	TypeValidation   Type = "VALIDATION_ERROR"
	TypeRequirement  Type = "REQUIREMENT_FAILED"
	TypeConflict     Type = "CONFLICT"
	TypeUnauthorized Type = "UNAUTHORIZED"
	TypeForbidden    Type = "FORBIDDEN"
	TypeNotFound     Type = "NOT_FOUND"
	TypeInternal     Type = "INTERNAL_ERROR"
)

type AppError struct {
	error
	Type    Type
	Message string
	Key     string
	Cause   error
}

func (e *AppError) Error() string {
	return fmt.Sprintf("[%s] %s", e.Type, e.Message)
}

func (e *AppError) Unwrap() error {
	return e.Cause
}

// --- Specific Application Error Constructors ---

func Validation(err error) error {
	return wrap(err, TypeValidation)
}

func Conflict(err error) error {
	return wrap(err, TypeConflict)
}

func Forbidden(err error) error {
	return wrap(err, TypeForbidden)
}

func NotFound(err error) error {
	return wrap(err, TypeNotFound)
}

func Internal(err error) error {
	return wrap(err, TypeInternal)
}

func Unauthorized(err error) error {
	return wrap(err, TypeUnauthorized)
}

// Internal helper to extract domain metadata
func wrap(err error, t Type) error {
	if err == nil {
		return nil
	}

	appErr := &AppError{
		Type:    t,
		Message: err.Error(),
		Cause:   err,
	}

	// If it's a DomainError, we extract the field key for the UI
	if dErr, ok := err.(derr.DomainError); ok {
		appErr.Key = dErr.Key()
	}

	return appErr
}
