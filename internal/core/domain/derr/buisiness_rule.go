package derr

import "fmt"

// --- Identity & State Rules ---

type ErrUserDeleted struct{ UserID string }

func NewErrUserDeleted(userID string) *ErrUserDeleted { return &ErrUserDeleted{UserID: userID} }

func (e *ErrUserDeleted) Error() string { return fmt.Sprintf("user '%s' has been deleted", e.UserID) }

func (e *ErrUserDeleted) Code() ErrorCode { return CodeBusinessRule }

type ErrInactiveUser struct{ UserID string }

func NewErrInactiveUser(userID string) *ErrInactiveUser { return &ErrInactiveUser{UserID: userID} }

func (e *ErrInactiveUser) Error() string { return fmt.Sprintf("user '%s' is inactive", e.UserID) }

func (e *ErrInactiveUser) Code() ErrorCode { return CodeBusinessRule }

type ErrMinimumRolesRequired struct {
	UserID   string
	MinCount uint8
}

func NewErrMinimumRolesRequired(userID string) *ErrMinimumRolesRequired {
	return &ErrMinimumRolesRequired{UserID: userID, MinCount: 1}
}

func (e *ErrMinimumRolesRequired) Error() string {
	return fmt.Sprintf("user %s must have at least %d role(s)", e.UserID, e.MinCount)
}
func (e *ErrMinimumRolesRequired) Code() ErrorCode { return CodeBusinessRule }

// --- Token Rules ---

type ErrTokenDoesNotBelongToDevice struct {
	SessionRenewalRawTokenID string
	DeviceID                 string
}

func NewErrTokenDoesNotBelongToDevice(tokenID, deviceID string) *ErrTokenDoesNotBelongToDevice {
	return &ErrTokenDoesNotBelongToDevice{SessionRenewalRawTokenID: tokenID, DeviceID: deviceID}
}

func (e *ErrTokenDoesNotBelongToDevice) Error() string {
	return fmt.Sprintf("security violation: token '%s' does not belong to device '%s'", e.SessionRenewalRawTokenID, e.DeviceID)
}

func (e *ErrTokenDoesNotBelongToDevice) Code() ErrorCode { return CodeBusinessRule }

// --- System & Policy Rules ---

type ErrDefaultRoleMissing struct{ RoleName string }

func NewErrDefaultRoleMissing(roleName string) *ErrDefaultRoleMissing {
	return &ErrDefaultRoleMissing{RoleName: roleName}
}
func (e *ErrDefaultRoleMissing) Error() string {
	return fmt.Sprintf("system error: default role '%s' could not be found", e.RoleName)
}
func (e *ErrDefaultRoleMissing) Code() ErrorCode { return CodeBusinessRule }
