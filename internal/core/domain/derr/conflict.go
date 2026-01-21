package derr

import "fmt"

// --- Uniqueness & Registration ---

type ErrEmailAlreadyUsed struct {
	Email string
}

func NewErrEmailAlreadyUsed(email string) *ErrEmailAlreadyUsed {
	return &ErrEmailAlreadyUsed{Email: email}
}

func (e *ErrEmailAlreadyUsed) Error() string {
	return fmt.Sprintf("email '%s' is already registered", e.Email)
}

func (e *ErrEmailAlreadyUsed) Code() ErrorCode { return CodeConflict }

// --- User State Conflicts ---

type ErrUserAlreadyActive struct {
	UserID string
}

func NewErrUserAlreadyActive(userID string) *ErrUserAlreadyActive {
	return &ErrUserAlreadyActive{UserID: userID}
}

func (e *ErrUserAlreadyActive) Error() string {
	return fmt.Sprintf("user '%s' is already active", e.UserID)
}

func (e *ErrUserAlreadyActive) Code() ErrorCode { return CodeConflict }

type ErrUserAlreadyInactive struct {
	UserID string
}

func NewErrUserAlreadyInactive(userID string) *ErrUserAlreadyInactive {
	return &ErrUserAlreadyInactive{UserID: userID}
}

func (e *ErrUserAlreadyInactive) Error() string {
	return fmt.Sprintf("user '%s' is already inactive", e.UserID)
}

func (e *ErrUserAlreadyInactive) Code() ErrorCode { return CodeConflict }

// --- Device State Conflicts ---

type ErrDeviceAlreadyActive struct {
	DeviceID string
}

func NewErrDeviceAlreadyActive(deviceID string) *ErrDeviceAlreadyActive {
	return &ErrDeviceAlreadyActive{DeviceID: deviceID}
}

func (e *ErrDeviceAlreadyActive) Error() string {
	return fmt.Sprintf("device '%s' is already active", e.DeviceID)
}

func (e *ErrDeviceAlreadyActive) Code() ErrorCode { return CodeConflict }

type ErrDeviceAlreadyInactive struct {
	DeviceID string
}

func NewErrDeviceAlreadyInactive(deviceID string) *ErrDeviceAlreadyInactive {
	return &ErrDeviceAlreadyInactive{DeviceID: deviceID}
}

func (e *ErrDeviceAlreadyInactive) Error() string {
	return fmt.Sprintf("device '%s' is already inactive", e.DeviceID)
}

func (e *ErrDeviceAlreadyInactive) Code() ErrorCode { return CodeConflict }

// --- Assignment Conflicts ---

type ErrRoleAlreadyAssignedToUser struct {
	RoleID string
	UserID string
}

func NewErrRoleAlreadyAssignedToUser(roleID, userID string) *ErrRoleAlreadyAssignedToUser {
	return &ErrRoleAlreadyAssignedToUser{RoleID: roleID, UserID: userID}
}

func (e *ErrRoleAlreadyAssignedToUser) Error() string {
	return fmt.Sprintf("role '%s' has already been assigned to user '%s'", e.RoleID, e.UserID)
}

func (e *ErrRoleAlreadyAssignedToUser) Code() ErrorCode { return CodeConflict }
