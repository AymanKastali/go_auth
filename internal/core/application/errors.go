package application

import (
	"errors"
	"go_auth/internal/core/domain"
)

type AppErrorCode string

const (
	AppErrInternal      AppErrorCode = "INTERNAL_ERROR"
	AppErrBadRequest    AppErrorCode = "BAD_REQUEST"
	AppErrUnauthorized  AppErrorCode = "UNAUTHORIZED"
	AppErrForbidden     AppErrorCode = "FORBIDDEN"
	AppErrUnprocessable AppErrorCode = "UNPROCESSABLE"
	AppErrNotFound      AppErrorCode = "NOT_FOUND"
	AppErrConflict      AppErrorCode = "CONFLICT"
)

type AppError struct {
	Code    AppErrorCode
	Message string
	Err     error
}

func (e *AppError) Error() string {
	if e == nil {
		return "unknown application error"
	}
	if e.Message != "" {
		return e.Message
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return string(e.Code)
}

func MapToAppError(err error) error {
	if err == nil {
		return nil
	}

	var domainErr domain.DomainError
	// Check if it's a known Domain Error
	if errors.As(err, &domainErr) {
		switch domainErr.Code() {
		case domain.CodeValidation:
			return &AppError{Code: AppErrBadRequest, Message: domainErr.Error(), Err: err}
		case domain.CodeConflict:
			return &AppError{Code: AppErrConflict, Message: domainErr.Error(), Err: err}
		case domain.CodeNotFound:
			return &AppError{Code: AppErrNotFound, Message: domainErr.Error(), Err: err}
		case domain.CodeBusinessRule:
			return &AppError{Code: AppErrUnprocessable, Message: domainErr.Error(), Err: err}
		case domain.CodeForbidden:
			return &AppError{Code: AppErrForbidden, Message: domainErr.Error(), Err: err}
		}
	}

	// Fallback for unexpected errors (like DB connection failures)
	return &AppError{
		Code:    AppErrInternal,
		Message: "an unexpected error occurred",
		Err:     err,
	}
}
