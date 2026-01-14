package apperr

import (
	"errors"
	"go_auth/internal/core/domain/derr"
)

// Kind represents the category of the application-level failure.
// It is agnostic of the transport layer (HTTP, gRPC, etc.).
type Kind int

const (
	KindInternal        Kind = iota // Unexpected system failures (DB down, disk full)
	KindInvalid                     // User input or request format is logically incorrect
	KindUnauthenticated             // The identity of the requester is not verified
	KindUnauthorized                // Identity verified, but lacks permission for this action
	KindConflict                    // State of the system prevents this specific operation
	KindNotFound                    // A resource required for the flow does not exist
)

// AppError represents a failure in a business use case orchestration.
type AppError struct {
	Kind      Kind   // The category of error
	Message   string // Human-readable description of the error
	RequestID string // Correlation ID for tracing logs
	Err       error  // The underlying root cause (derr, pgerr, or raw error)
}

// Error implements the standard error interface.
func (e *AppError) Error() string {
	return e.Message
}

// Unwrap allows standard library functions like errors.Is and errors.As to access the root cause.
func (e *AppError) Unwrap() error {
	return e.Err
}

// --- Mapper: Domain -> Application ---

// FromDomain transforms a Domain-level error into an Application-level error.
// It ensures that specific business rules are categorized into workflow "Kinds".
func FromDomain(err error, requestID string) error {
	if err == nil {
		return nil
	}

	// If it's already an AppError, don't wrap it again
	var ae *AppError
	if errors.As(err, &ae) {
		return ae
	}

	// Map Domain Error codes to Application Kinds
	var de derr.DomainError
	if errors.As(err, &de) {
		switch de.Code() {
		case derr.CodeValidation:
			return &AppError{Kind: KindInvalid, Message: de.Error(), RequestID: requestID, Err: err}
		case derr.CodeConflict:
			return &AppError{Kind: KindConflict, Message: de.Error(), RequestID: requestID, Err: err}
		case derr.CodePermissionDenied:
			return &AppError{Kind: KindUnauthorized, Message: de.Error(), RequestID: requestID, Err: err}
		}
	}

	// Default: Treat unknown errors or infrastructure failures as Internal
	return &AppError{
		Kind:      KindInternal,
		Message:   "An unexpected error occurred during processing",
		RequestID: requestID,
		Err:       err,
	}
}

// --- Actionable Helpers ---
// These are used by Use Cases for flow-specific logic that isn't strictly an entity invariant.

func Invalid(msg, rid string, err error) error {
	return &AppError{Kind: KindInvalid, Message: msg, RequestID: rid, Err: err}
}

func Unauthenticated(msg, rid string, err error) error {
	return &AppError{Kind: KindUnauthenticated, Message: msg, RequestID: rid, Err: err}
}

func Unauthorized(msg, rid string, err error) error {
	return &AppError{Kind: KindUnauthorized, Message: msg, RequestID: rid, Err: err}
}

func NotFound(msg, rid string, err error) error {
	return &AppError{Kind: KindNotFound, Message: msg, RequestID: rid, Err: err}
}

func Conflict(msg, rid string, err error) error {
	return &AppError{Kind: KindConflict, Message: msg, RequestID: rid, Err: err}
}

func Internal(msg, rid string, err error) error {
	return &AppError{Kind: KindInternal, Message: msg, RequestID: rid, Err: err}
}

// package apperr

// import (
// 	"errors"
// 	"fmt"
// 	"go_auth/internal/core/domain/derr"
// )

// // AppError is the interface used by controllers and transport layers.
// type AppError interface {
// 	error
// 	Code() derr.Code
// 	Cause() error
// 	TraceID() string
// }

// type appError struct {
// 	code      derr.Code
// 	message   string
// 	cause     error
// 	requestID string
// }

// var _ AppError = (*appError)(nil)

// func (e *appError) Error() string   { return e.message }
// func (e *appError) Code() derr.Code { return e.code }
// func (e *appError) Cause() error    { return e.cause }
// func (e *appError) TraceID() string { return e.requestID }
// func (e *appError) Unwrap() error   { return e.cause }

// // FromDomain converts a DomainError into an AppError, preserving the code and message.
// func FromDomain(err error, requestID string) AppError {
// 	if err == nil {
// 		return nil
// 	}

// 	var dErr derr.DomainError
// 	if errors.As(err, &dErr) {
// 		return &appError{
// 			code:      dErr.Code(),
// 			message:   dErr.Error(),
// 			cause:     err,
// 			requestID: requestID,
// 		}
// 	}

// 	return Internal("An unexpected error occurred", requestID, err)
// }

// // --- Application Layer Factory Methods ---

// // BadRequest (400) - For general input/request failures
// func BadRequest(msg string, requestID string, cause error) AppError {
// 	return newErr(derr.CodeValidation, msg, requestID, cause)
// }

// // Unauthorized (401) - Specifically for authentication failures (Login/Token)
// // Note: We use CodePermissionDenied or a custom code if you prefer
// func Unauthorized(msg string, requestID string, cause error) AppError {
// 	return newErr(derr.CodePermissionDenied, msg, requestID, cause)
// }

// // Forbidden (403) - For users who are logged in but lack permission
// func Forbidden(msg string, requestID string, cause error) AppError {
// 	return newErr(derr.CodePermissionDenied, msg, requestID, cause)
// }

// // NotFound (404) - For application-level missing resources (e.g., URL routes)
// func NotFound(msg string, requestID string, cause error) AppError {
// 	return newErr(derr.CodeNotFound, msg, requestID, cause)
// }

// // Conflict (409) - For state-based failures
// func Conflict(msg string, requestID string, cause error) AppError {
// 	return newErr(derr.CodeConflict, msg, requestID, cause)
// }

// // Internal (500) - For infrastructure crashes (DB down, JSON marshal failure)
// func Internal(msg string, requestID string, cause error) AppError {
// 	return newErr(derr.CodeInternal, msg, requestID, cause)
// }

// func newErr(code derr.Code, msg string, requestID string, cause error) AppError {
// 	return &appError{
// 		code:      code,
// 		message:   fmt.Sprintf("[Application Error]: %s", msg),
// 		requestID: requestID,
// 		cause:     cause,
// 	}
// }
