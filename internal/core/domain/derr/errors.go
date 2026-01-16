package derr

import (
	"fmt"
)

type Code string

const (
	CodeNotFound   Code = "NOT_FOUND"
	CodeValidation Code = "VALIDATION"
	CodeConflict   Code = "CONFLICT"
	CodeForbidden  Code = "FORBIDDEN"
	CodeInternal   Code = "INTERNAL_ERROR"
)

// DomainError is now exported so JSON marshaling works.
type DomainError struct {
	Inner   error          `json:"-"`
	Type    Code           `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

func (e *DomainError) Error() string {
	if e.Inner != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Inner)
	}
	return e.Message
}
func (e *DomainError) Unwrap() error { return e.Inner }

// --- Internal Helpers ---

func newErr(code Code, msg string, details map[string]any) *DomainError {
	return &DomainError{
		Type:    code,
		Message: msg,
		Details: details,
	}
}

func validation(msg string, field string, reason string) *DomainError {
	return newErr(CodeValidation, msg, map[string]any{
		"field":  field,
		"reason": reason,
	})
}

func required(field string) *DomainError {
	return validation(fmt.Sprintf("%s is required", field), field, "required")
}

// --- 1. Identity & Resource Validation (Required) ---

func ErrUserIDRequired() *DomainError      { return required("user_id") }
func ErrEmailRequired() *DomainError       { return required("email") }
func ErrPasswordRequired() *DomainError    { return required("password") }
func ErrStatusRequired() *DomainError      { return required("status") }
func ErrCurrentTimeRequired() *DomainError { return required("current_time") }
func ErrRoleIDRequired() *DomainError      { return required("role_id") }
func ErrRoleNameRequired() *DomainError    { return required("role_name") }
func ErrDeviceIDRequired() *DomainError    { return required("device_id") }
func ErrTokenRequired() *DomainError       { return required("token") }
func ErrTokenIDRequired() *DomainError     { return required("token_id") }
func ErrExpiresAtRequired() *DomainError   { return required("expiration_date") }

// --- 2. Business Rule Violations (Rules) ---

func ErrInvalidEmail() *DomainError {
	return validation("email format is invalid", "email", "format")
}

func ErrExpirationInPast() *DomainError {
	return validation("expiration date cannot be in the past", "expires_at", "past_date")
}

func ErrMinimumRolesRequirement(min int) *DomainError {
	return validation(
		fmt.Sprintf("at least %d role(s) must be assigned", min),
		"roles",
		fmt.Sprintf("min_%d", min),
	)
}

func ErrRoleNotAssigned(roleID string) *DomainError {
	return validation("role is not assigned to this user", "role_id", "not_assigned")
}

func ErrRoleAlreadyAssigned(roleID string) *DomainError {
	return validation("role is already assigned to this user", "role_id", "already_assigned")
}

func ErrPasswordTooShort(min int) *DomainError {
	err := validation(
		fmt.Sprintf("password must be at least %d characters long", min),
		"password",
		"too_short",
	)
	err.Details["min_length"] = min
	return err
}

func ErrPasswordTooWeak(requirements string) *DomainError {
	return validation(
		fmt.Sprintf("password does not meet complexity requirements: %s", requirements),
		"password",
		"low_entropy",
	)
}

func ErrPasswordMismatch() *DomainError {
	return validation("invalid credentials provided", "password", "mismatch")
}

func ErrTokenExpired(tokenID string) *DomainError {
	return newErr(CodeValidation, "the provided token has expired", map[string]any{
		"token_id": tokenID,
		"reason":   "expired",
	})
}

// --- 3. Access & Ownership Errors (Forbidden) ---

func ErrTokenDoesNotBelongToDevice(tokenID, deviceID string) *DomainError {
	return newErr(CodeForbidden, "access denied: token/device mismatch", map[string]any{
		"token_id":  tokenID,
		"device_id": deviceID,
	})
}

func ErrDeviceDoesNotBelongToUser(deviceID, userID string) *DomainError {
	return newErr(CodeForbidden, "access denied: device/user mismatch", map[string]any{
		"device_id": deviceID,
		"user_id":   userID,
	})
}

// --- 4. State Management Errors (Conflict) ---

func ErrUserDeleted(userID string) *DomainError {
	return newErr(CodeConflict, "action cannot be performed on a deleted user", map[string]any{"user_id": userID})
}
func ErrTokenDeleted(tokenID string) *DomainError {
	return newErr(CodeConflict, "action cannot be performed on a deleted token", map[string]any{"token_id": tokenID})
}

func ErrDeviceRevoked(deviceID string) *DomainError {
	return newErr(CodeConflict, "device session has been revoked", map[string]any{"device_id": deviceID})
}

func ErrTokenRevoked(tokenID string) *DomainError {
	return newErr(CodeConflict, "token has been revoked", map[string]any{"token_id": tokenID})
}

func ErrStateConflict(resource, id, currentState string) *DomainError {
	return newErr(CodeConflict, fmt.Sprintf("%s %s is already %s", resource, id, currentState), map[string]any{
		"resource": resource,
		"id":       id,
		"state":    currentState,
	})
}

// Simplified "Already in Status" usage
func ErrUserAlreadyActive(id string) *DomainError   { return ErrStateConflict("user", id, "active") }
func ErrUserAlreadyInactive(id string) *DomainError { return ErrStateConflict("user", id, "inactive") }
func ErrDeviceAlreadyInactive(id string) *DomainError {
	return ErrStateConflict("device", id, "inactive")
}
func ErrDeviceAlreadyActive(id string) *DomainError { return ErrStateConflict("device", id, "active") }
