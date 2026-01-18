package apperr

import (
	"errors"
	"go_auth/internal/adapters/persistence/postgres/pgerr"
	"go_auth/internal/core/domain/derr"
)

func Map(err error) *AppError {
	if err == nil {
		return nil
	}

	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr
	}

	var domainErr *derr.DomainError
	if errors.As(err, &domainErr) {
		return &AppError{
			Type:    mapDomainCode(domainErr.Type),
			Message: domainErr.Message,
			Details: domainErr.Details,
			Cause:   domainErr,
		}
	}

	if pgerr.IsAlreadyExists(err) {
		return &AppError{
			Type:    TypeConflict,
			Message: "A resource with this information already exists",
			Cause:   err,
		}
	}

	return &AppError{
		Type:    TypeInternal,
		Message: "An unexpected system error occurred",
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
