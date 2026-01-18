package apperr

import "fmt"

func Internal(msg string, cause error) *AppError {
	return &AppError{
		Type:    TypeInternal,
		Message: msg,
		Cause:   cause,
	}
}

func Validation(msg string, details map[string]any) *AppError {
	return &AppError{
		Type:    TypeValidation,
		Message: msg,
		Details: details,
	}
}

func NotFound(resource, id string) *AppError {
	return &AppError{
		Type:    TypeNotFound,
		Message: fmt.Sprintf("%s with ID %s not found", resource, id),
		Details: map[string]any{"resource": resource, "id": id},
	}
}

func Conflict(msg string, cause error) *AppError {
	return &AppError{
		Type:    TypeConflict,
		Message: msg,
		Cause:   cause,
	}
}

func Forbidden(msg string, cause error) *AppError {
	return &AppError{
		Type:    TypeForbidden,
		Message: msg,
		Cause:   cause,
	}
}

func Unauthorized(msg string, cause error) *AppError {
	return &AppError{
		Type:    TypeUnauthorized,
		Message: msg,
		Cause:   cause,
	}
}
