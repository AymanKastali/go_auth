package apperr

import (
	"fmt"
)

type ErrorType string

const (
	TypeInternal     ErrorType = "INTERNAL"     // 500
	TypeValidation   ErrorType = "VALIDATION"   // 400/422
	TypeNotFound     ErrorType = "NOT_FOUND"    // 404
	TypeConflict     ErrorType = "CONFLICT"     // 409
	TypeForbidden    ErrorType = "FORBIDDEN"    // 403
	TypeUnauthorized ErrorType = "UNAUTHORIZED" // 401
)

// AppError is the final object returned by Use Cases
type AppError struct {
	Type    ErrorType      `json:"type"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
	Cause   error          `json:"-"` // Hidden from user, kept for logging
}

func (e *AppError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

func (e *AppError) Unwrap() error {
	return e.Cause
}
