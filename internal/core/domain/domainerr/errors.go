package domainerr

import (
	"errors"
	"fmt"
	"strings"
)

const (
	CodeRequiredAttr = 1001
	CodeInvalidValue = 1002
)

type DomainError struct {
	Code        uint
	Message, Op string
	Err         error // The underlying cause (optional)
}

func pluralize(count int) string {
	if count == 1 {
		return "is"
	}
	return "are"
}

func NewDomainRequiredAttrError(attr string, op string) *DomainError {
	return &DomainError{
		Code:    CodeRequiredAttr,
		Message: fmt.Sprintf("%s is required", attr),
		Op:      op,
	}
}

func NewDomainRequiredAttrsError(attrs []string, op string, err error) *DomainError {
	if len(attrs) == 0 {
		return nil
	}

	message := fmt.Sprintf("%s %s required",
		strings.Join(attrs, ", "),
		pluralize(len(attrs)),
	)

	return &DomainError{
		Code:    CodeRequiredAttr,
		Message: message,
		Op:      op,
		Err:     err,
	}
}

func NewDomainInvalidValueError(attr string, op string, err error) *DomainError {
	return &DomainError{
		Code:    CodeInvalidValue,
		Message: fmt.Sprintf("%s is invalid", attr),
		Op:      op,
		Err:     err,
	}
}
func (e *DomainError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("[%s] %d: %s (cause: %v)", e.Op, e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("[%s] %d: %s", e.Op, e.Code, e.Message)
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
