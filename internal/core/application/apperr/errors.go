package apperr

import (
	"errors"
	"go_auth/internal/core/domain/derr"
)

// AppError is the interface used by controllers and transport layers.
type AppError interface {
	error
	Code() derr.Code
	Cause() error
	TraceID() string
}

type appError struct {
	code      derr.Code
	message   string
	cause     error
	requestID string
}

var _ AppError = (*appError)(nil)

func (e *appError) Error() string   { return e.message }
func (e *appError) Code() derr.Code { return e.code }
func (e *appError) Cause() error    { return e.cause }
func (e *appError) TraceID() string { return e.requestID }
func (e *appError) Unwrap() error   { return e.cause }

// FromDomain converts a DomainError into an AppError, preserving the code and message.
func FromDomain(err error, requestID string) AppError {
	if err == nil {
		return nil
	}

	var dErr derr.DomainError
	if errors.As(err, &dErr) {
		return &appError{
			code:      dErr.Code(),
			message:   dErr.Error(),
			cause:     err,
			requestID: requestID,
		}
	}

	return Internal("An unexpected error occurred", requestID, err)
}

// --- Application Layer Factory Methods ---

// BadRequest (400) - For general input/request failures
func BadRequest(msg string, requestID string, cause error) AppError {
	return &appError{code: derr.CodeValidation, message: msg, requestID: requestID, cause: cause}
}

// Unauthorized (401) - Specifically for authentication failures (Login/Token)
// Note: We use CodePermissionDenied or a custom code if you prefer
func Unauthorized(msg string, requestID string, cause error) AppError {
	return &appError{code: derr.CodePermissionDenied, message: msg, requestID: requestID, cause: cause}
}

// Forbidden (403) - For users who are logged in but lack permission
func Forbidden(msg string, requestID string, cause error) AppError {
	return &appError{code: derr.CodePermissionDenied, message: msg, requestID: requestID, cause: cause}
}

// NotFound (404) - For application-level missing resources (e.g., URL routes)
func NotFound(msg string, requestID string, cause error) AppError {
	return &appError{code: derr.CodeNotFound, message: msg, requestID: requestID, cause: cause}
}

// Conflict (409) - For state-based failures
func Conflict(msg string, requestID string, cause error) AppError {
	return &appError{code: derr.CodeConflict, message: msg, requestID: requestID, cause: cause}
}

// Internal (500) - For infrastructure crashes (DB down, JSON marshal failure)
func Internal(msg string, requestID string, cause error) AppError {
	return &appError{code: derr.CodeInternal, message: msg, requestID: requestID, cause: cause}
}
