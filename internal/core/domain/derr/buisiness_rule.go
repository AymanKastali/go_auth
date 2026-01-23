package derr

import "fmt"

// --- Identity & State Rules ---

type ErrUserDeleted struct {
	UserID string
}

func NewErrUserDeleted(userID string) *ErrUserDeleted {
	return &ErrUserDeleted{UserID: userID}
}

func (e *ErrUserDeleted) Error() string {
	return fmt.Sprintf("user '%s' has been deleted", e.UserID)
}

func (e *ErrUserDeleted) Code() ErrorCode { return CodeBusinessRule }

type ErrInactiveUser struct {
	UserID string
}

func NewErrInactiveUser(userID string) *ErrInactiveUser {
	return &ErrInactiveUser{UserID: userID}
}

func (e *ErrInactiveUser) Error() string {
	return fmt.Sprintf("user '%s' is inactive", e.UserID)
}

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

// --- Security & Session Rules ---

type ErrSessionCompromised struct {
	UserID string
}

func NewErrSessionCompromised(userID string) *ErrSessionCompromised {
	return &ErrSessionCompromised{UserID: userID}
}

func (e *ErrSessionCompromised) Error() string {
	return fmt.Sprintf("security alert: session for user %s has been compromised (token reuse detected)", e.UserID)
}

func (e *ErrSessionCompromised) Code() ErrorCode { return CodeBusinessRule }

type ErrDeviceDoesNotBelongToUser struct {
	UserID   string
	DeviceID string
}

func NewErrDeviceDoesNotBelongToUser(userID, deviceID string) *ErrDeviceDoesNotBelongToUser {
	return &ErrDeviceDoesNotBelongToUser{UserID: userID, DeviceID: deviceID}
}

func (e *ErrDeviceDoesNotBelongToUser) Error() string {
	return fmt.Sprintf("security violation: device '%s' does not belong to user '%s'", e.DeviceID, e.UserID)
}

func (e *ErrDeviceDoesNotBelongToUser) Code() ErrorCode { return CodeBusinessRule }

type ErrDeviceRevoked struct {
	DeviceID string
}

func NewErrDeviceRevoked(deviceID string) *ErrDeviceRevoked {
	return &ErrDeviceRevoked{DeviceID: deviceID}
}

func (e *ErrDeviceRevoked) Error() string {
	return fmt.Sprintf("device '%s' has been revoked", e.DeviceID)
}

func (e *ErrDeviceRevoked) Code() ErrorCode { return CodeBusinessRule }

// --- Token Rules ---

type ErrSessionRenewalTokenRevoked struct {
	SessionRenewalTokenID string
}

func NewErrSessionRenewalTokenRevoked(tokenID string) *ErrSessionRenewalTokenRevoked {
	return &ErrSessionRenewalTokenRevoked{SessionRenewalTokenID: tokenID}
}

func (e *ErrSessionRenewalTokenRevoked) Error() string {
	return fmt.Sprintf("session renewal token '%s' has been revoked", e.SessionRenewalTokenID)
}

func (e *ErrSessionRenewalTokenRevoked) Code() ErrorCode { return CodeBusinessRule }

type ErrSessionRenewalTokenExpired struct {
	SessionRenewalTokenID string
}

func NewErrSessionRenewalTokenExpired(tokenID string) *ErrSessionRenewalTokenExpired {
	return &ErrSessionRenewalTokenExpired{SessionRenewalTokenID: tokenID}
}

func (e *ErrSessionRenewalTokenExpired) Error() string {
	return fmt.Sprintf("session renewal token '%s' has expired", e.SessionRenewalTokenID)
}

func (e *ErrSessionRenewalTokenExpired) Code() ErrorCode { return CodeBusinessRule }

type ErrTokenDoesNotBelongToDevice struct {
	SessionRenewalTokenID string
	DeviceID              string
}

func NewErrTokenDoesNotBelongToDevice(tokenID, deviceID string) *ErrTokenDoesNotBelongToDevice {
	return &ErrTokenDoesNotBelongToDevice{SessionRenewalTokenID: tokenID, DeviceID: deviceID}
}

func (e *ErrTokenDoesNotBelongToDevice) Error() string {
	return fmt.Sprintf("security violation: token '%s' does not belong to device '%s'", e.SessionRenewalTokenID, e.DeviceID)
}

func (e *ErrTokenDoesNotBelongToDevice) Code() ErrorCode { return CodeBusinessRule }

// --- System & Policy Rules ---

type ErrDefaultRoleMissing struct {
	RoleName string
}

func NewErrDefaultRoleMissing(roleName string) *ErrDefaultRoleMissing {
	return &ErrDefaultRoleMissing{RoleName: roleName}
}

func (e *ErrDefaultRoleMissing) Error() string {
	return fmt.Sprintf("system error: default role '%s' could not be found", e.RoleName)
}

func (e *ErrDefaultRoleMissing) Code() ErrorCode { return CodeBusinessRule }
