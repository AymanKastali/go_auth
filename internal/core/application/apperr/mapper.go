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

	var dErr derr.DomainError
	if errors.As(err, &dErr) {
		return &AppError{
			Type:    mapDomainCode(dErr.Code()),
			Message: dErr.Error(),
			Cause:   dErr,
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

func mapDomainCode(code derr.ErrorCode) ErrorType {
	switch code {
	case derr.CodeValidation:
		return TypeValidation
	case derr.CodeConflict:
		return TypeConflict
	case derr.CodeBusinessRule:
		return TypeUnprocessable
	default:
		return TypeInternal
	}
}
