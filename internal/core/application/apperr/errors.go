package apperr

import (
	"errors"
	"go_auth/internal/core/domain/domainerr"
)

type Code uint16

const (
	CodeInvalidCredentials Code = 2001
	CodeInvalidValue       Code = 2003
	CodeUserInactive       Code = 2004
	CodeDeviceNotUsable    Code = 2005
	CodeDeviceNotFound     Code = 2006
	CodeEmailExists        Code = 2007
	CodeInternal           Code = 2008
)

type AppError struct {
	code Code
	msg  string
	err  error
}

func (e *AppError) Error() string {
	return e.msg
}

func (e *AppError) Code() Code {
	return e.code
}

func (e *AppError) Unwrap() error {
	return e.err
}

// Enables errors.Is(err, ErrX)
func (e *AppError) Is(target error) bool {
	t, ok := target.(*AppError)
	if !ok {
		return false
	}
	return e.code == t.code
}

var (
	ErrInvalidCredentials = &AppError{
		code: CodeInvalidCredentials,
		msg:  "invalid credentials",
	}

	ErrInvalidValue = &AppError{
		code: CodeInvalidValue,
		msg:  "invalid value",
	}

	ErrUserInactive = &AppError{
		code: CodeUserInactive,
		msg:  "user is inactive",
	}

	ErrDeviceNotUsable = &AppError{
		code: CodeDeviceNotUsable,
		msg:  "device is not usable",
	}

	ErrDeviceNotFound = &AppError{
		code: CodeDeviceNotFound,
		msg:  "device not found",
	}

	ErrEmailAlreadyRegistered = &AppError{
		code: CodeEmailExists,
		msg:  "email already registered",
	}

	ErrInternal = &AppError{
		code: CodeInternal,
		msg:  "internal server error",
	}
)

var domainToAppMap = map[domainerr.Code]*AppError{
	domainerr.CodeRequiredAttr:    ErrInternal,
	domainerr.CodeInvalidValue:    ErrInvalidValue,
	domainerr.CodeInvalidState:    ErrUserInactive,
	domainerr.CodeOperationDenied: ErrDeviceNotUsable,
}

func wrap(appErr *AppError, cause error) *AppError {
	return &AppError{
		code: appErr.code,
		msg:  appErr.msg,
		err:  cause,
	}
}

func FromDomainError(err error) error {
	if err == nil {
		return nil
	}

	var dErr *domainerr.DomainError
	if !errors.As(err, &dErr) {
		return wrap(ErrInternal, err)
	}

	appErr, ok := domainToAppMap[dErr.Code()]
	if !ok {
		return wrap(ErrInternal, err)
	}

	return wrap(appErr, err)
}
