package apperr

import (
	"errors"
	"go_auth/internal/core/domain/domainerr"
)

var (
	ErrInvalidCredentials     = errors.New("invalid credentials")
	ErrUserInactive           = errors.New("user is inactive")
	ErrDeviceNotUsable        = errors.New("device is not usable")
	ErrDeviceNotFound         = errors.New("device not found")
	ErrEmailAlreadyRegistered = errors.New("email already registered")
	ErrInternal               = errors.New("internal server error")
)

func FromDomainError(err error) error {
	if err == nil {
		return nil
	}

	switch e := err.(type) {
	case *domainerr.DomainError:
		switch e.Code() {
		case domainerr.CodeRequiredAttr:
			// Usually validation already handled
			return ErrInternal
		case domainerr.CodeInvalidValue:
			// Map invalid value errors to a generic application error
			return ErrDeviceNotUsable
		case domainerr.CodeInvalidState:
			return ErrUserInactive
		case domainerr.CodeOperationDenied:
			return ErrDeviceNotUsable
		default:
			return ErrInternal
		}
	default:
		// Any other unknown error
		return ErrInternal
	}
}
