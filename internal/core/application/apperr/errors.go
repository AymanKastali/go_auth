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
	TraceID string         `json:"trace_id"`
	Details map[string]any `json:"details,omitempty"`
	Cause   error          `json:"-"` // Hidden from user, kept for logging
}

func (e *AppError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s] %s: %v", e.TraceID, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s] %s", e.TraceID, e.Message)
}

func (e *AppError) Unwrap() error {
	return e.Cause
}
