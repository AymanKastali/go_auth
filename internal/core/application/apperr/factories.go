package apperr

import "fmt"

// Internal - 500: Unexpected system failures, config issues, or unhandled panics.
func Internal(msg string, traceID string, cause error) *AppError {
	return &AppError{
		Type:    TypeInternal,
		Message: msg,
		TraceID: traceID,
		Cause:   cause,
	}
}

// Validation - 400/422: Orchestration-level checks (e.g., DTO field mismatch).
func Validation(msg string, traceID string, details map[string]any) *AppError {
	return &AppError{
		Type:    TypeValidation,
		Message: msg,
		TraceID: traceID,
		Details: details,
	}
}

// NotFound - 404: When an ID exists in the request but not in the system.
func NotFound(resource, id, traceID string) *AppError {
	return &AppError{
		Type:    TypeNotFound,
		Message: fmt.Sprintf("%s with ID %s not found", resource, id),
		TraceID: traceID,
		Details: map[string]any{"resource": resource, "id": id},
	}
}

// Conflict - 409: Business state conflicts (e.g., user already exists).
func Conflict(msg string, traceID string, cause error) *AppError {
	return &AppError{
		Type:    TypeConflict,
		Message: msg,
		TraceID: traceID,
		Cause:   cause,
	}
}

// Forbidden - 403: Authenticated but lacks permission for this specific action.
func Forbidden(msg string, traceID string, cause error) *AppError {
	return &AppError{
		Type:    TypeForbidden,
		Message: msg,
		TraceID: traceID,
		Cause:   cause,
	}
}

// Unauthorized - 401: Identity cannot be verified (Expired/Invalid Token).
func Unauthorized(msg string, traceID string, cause error) *AppError {
	return &AppError{
		Type:    TypeUnauthorized,
		Message: msg,
		TraceID: traceID,
		Cause:   cause,
	}
}
