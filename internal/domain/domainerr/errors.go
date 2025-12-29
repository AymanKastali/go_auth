package domainerr

import (
	"errors"
	"fmt"
)

const (
	CodeRequiredAttr = "domain_required_attr"
	CodeInvalidValue = "domain_invalid_value"
)

func NewDomainRequiredAttrError(attr string, op string) *DomainError {
	return &DomainError{
		Code:    CodeRequiredAttr,
		Message: fmt.Sprintf("%s is required", attr),
		Op:      op,
	}
}

type DomainError struct {
	Code, Message, Op string
	Err               error // The underlying cause (optional)
}

func (e *DomainError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("[%s] %s: %s (cause: %v)", e.Op, e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("[%s] %s: %s", e.Op, e.Code, e.Message)
}

func (e *DomainError) Unwrap() error {
	return e.Err
}

var (
	ErrInvalidCredentials          = errors.New("invalid credentials")
	ErrAccountDisabled             = errors.New("account disabled")
	ErrSessionExpired              = errors.New("session expired")
	ErrEmailAlreadyRegistered      = errors.New("email is already registered")
	ErrUserNotFound                = errors.New("user not found")
	ErrSessionNotFound             = errors.New("session not found")
	ErrUserNotMemberOfOrganization = errors.New("user is not a part of this organization")
	ErrInvalidToken                = errors.New("Invalid token")

	ErrDeviceRevoked     = errors.New("device is revoked")
	ErrDeviceInactive    = errors.New("device is inactive")
	ErrInvalidDeviceUser = errors.New("device does not belong to user")
	ErrInvalidDeviceID   = errors.New("invalid device id")

	ErrRefreshTokenRevoked = errors.New("refresh token revoked")
	ErrRefreshTokenExpired = errors.New("refresh token expired")
	ErrInvalidTokenUser    = errors.New("refresh token does not belong to user")
)
