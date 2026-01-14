package derr

import (
	"fmt"
)

type Code int

const (
	CodeValidation Code = iota
	CodeConflict
	CodePermissionDenied
)

type DomainError interface {
	error
	Code() Code
}

var _ DomainError = (*domainError)(nil)

type domainError struct {
	code    Code
	message string
}

func (e *domainError) Error() string { return e.message }
func (e *domainError) Code() Code    { return e.code }

// --- Helpers (Internal) ---

func newErr(code Code, msg string) DomainError {
	return &domainError{code: code, message: msg}
}

func newErrRequired(field string) DomainError {
	return newErr(CodeValidation, fmt.Sprintf("%s is required", field))
}

func newErrInvalid(field string) DomainError {
	return newErr(CodeValidation, fmt.Sprintf("%s is invalid", field))
}

// --- Validation Errors (Required) ---

func ErrUserIDRequired() DomainError      { return newErrRequired("user id") }
func ErrEmailRequired() DomainError       { return newErrRequired("email") }
func ErrPasswordRequired() DomainError    { return newErrRequired("password") }
func ErrStatusRequired() DomainError      { return newErrRequired("status") }
func ErrCurrentTimeRequired() DomainError { return newErrRequired("current time") }
func ErrRoleIDRequired() DomainError      { return newErrRequired("role id") }
func ErrRoleNameRequired() DomainError    { return newErrRequired("role name") }
func ErrDeviceIDRequired() DomainError    { return newErrRequired("device id") }
func ErrTokenRequired() DomainError       { return newErrRequired("token") }
func ErrTokenIDRequired() DomainError     { return newErrRequired("token id") }
func ErrExpiresAtRequired() DomainError   { return newErrRequired("expiration date") }

// --- Validation Errors (Rules) ---

func ErrInvalidEmail() DomainError { return newErrInvalid("email") }

func ErrExpirationInPast() DomainError {
	return newErr(CodeValidation, "expiration date cannot be in the past")
}

func ErrMinimumRolesRequirement(min int) DomainError {
	return newErr(CodeValidation, fmt.Sprintf("at least %d role(s) must be assigned", min))
}

func ErrRoleNotAssigned(roleID string) DomainError {
	return newErr(CodeValidation, fmt.Sprintf("role %s is not assigned to this user", roleID))
}

func ErrRoleAlreadyAssigned(roleID string) DomainError {
	return newErr(CodeValidation, fmt.Sprintf("role %s is already assigned to this user", roleID))
}

func ErrTokenExpired(tokenID string) DomainError {
	return newErr(CodeValidation, fmt.Sprintf("token %s is expired", tokenID))
}

// --- Permission / Ownership Errors ---

func ErrTokenDoesNotBelongToDevice(tokenID, deviceID string) DomainError {
	return newErr(CodePermissionDenied, fmt.Sprintf("token %s does not belong to device %s", tokenID, deviceID))
}

func ErrDeviceDoesNotBelongToUser(deviceID, userID string) DomainError {
	return newErr(CodePermissionDenied, fmt.Sprintf("device %s does not belong to user %s", deviceID, userID))
}

// --- Conflict Errors (State) ---

func ErrDeviceRevoked(deviceID string) DomainError {
	return newErr(CodeConflict, fmt.Sprintf("device %s is revoked", deviceID))
}

func ErrDeviceDeleted(deviceID string) DomainError {
	return newErr(CodeConflict, fmt.Sprintf("device %s is deleted", deviceID))
}

func ErrTokenRevoked(tokenID string) DomainError {
	return newErr(CodeConflict, fmt.Sprintf("token %s is revoked", tokenID))
}
func ErrTokenDeleted(tokenID string) DomainError {
	return newErr(CodeConflict, fmt.Sprintf("token %s is deleted", tokenID))
}
func ErrUserDeleted(userID string) DomainError {
	return newErr(CodeConflict, fmt.Sprintf("user %s is deleted", userID))
}

// Standardizing "Already In Status" phrasing
func ErrUserAlreadyActive(userID string) DomainError {
	return newErr(CodeConflict, fmt.Sprintf("user %s is already active", userID))
}

func ErrUserAlreadyInactive(userID string) DomainError {
	return newErr(CodeConflict, fmt.Sprintf("user %s is already inactive", userID))
}

func ErrDeviceAlreadyActive(deviceID string) DomainError {
	return newErr(CodeConflict, fmt.Sprintf("device %s is already active", deviceID))
}

func ErrDeviceAlreadyInactive(deviceID string) DomainError {
	return newErr(CodeConflict, fmt.Sprintf("device %s is already inactive", deviceID))
}
