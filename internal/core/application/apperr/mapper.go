package apperr

import (
	"errors"
	"go_auth/internal/adapters/persistence/postgres/pgerr"
	"go_auth/internal/core/domain/derr"
)

// Map transforms any error into a clean Application Error
func Map(err error, traceID string) *AppError {
	if err == nil {
		return nil
	}

	// 1. Check if it's already an AppError (Prevent double wrapping)
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr
	}

	// 2. Check if it's a Domain Error (derr)
	var domainErr *derr.DomainError
	if errors.As(err, &domainErr) {
		return &AppError{
			Type:    mapDomainCode(domainErr.Type),
			Message: domainErr.Message,
			Details: domainErr.Details,
			TraceID: traceID,
			Cause:   domainErr,
		}
	}

	// 3. Check for Infrastructure/Repo Behaviors (pgerr)
	if pgerr.IsAlreadyExists(err) {
		return &AppError{
			Type:    TypeConflict,
			Message: "A resource with this information already exists",
			TraceID: traceID,
			Cause:   err,
		}
	}

	// 4. Fallback: Critical/Internal Error
	return &AppError{
		Type:    TypeInternal,
		Message: "An unexpected system error occurred",
		TraceID: traceID,
		Cause:   err,
	}
}

func mapDomainCode(code derr.Code) ErrorType {
	switch code {
	case derr.CodeNotFound:
		return TypeNotFound
	case derr.CodeValidation:
		return TypeValidation
	case derr.CodeConflict:
		return TypeConflict
	case derr.CodeForbidden:
		return TypeForbidden
	default:
		return TypeInternal
	}
}
