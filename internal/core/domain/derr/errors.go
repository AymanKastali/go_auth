package derr

import (
	"errors"
	"fmt"
)

const (
	OpValidation = "Validation"
	OpRule       = "Business Rule"
	OpNotFound   = "Not Found" // Added for repository/resource consistency
)

type DomainError interface {
	error
	Domain()
	Unwrap() error
	Key() string
	Op() string
}

type domainError struct {
	op     string
	key    string
	reason error
}

func (e *domainError) Error() string {
	return fmt.Sprintf("[%s] %s: %v", e.op, e.key, e.reason)
}

func (e *domainError) Domain()       {}
func (e *domainError) Unwrap() error { return e.reason }
func (e *domainError) Key() string   { return e.key }
func (e *domainError) Op() string    { return e.op }

// --- Validation Factory (Input Integrity) ---

var NewValidation = validationFactory{}

type validationFactory struct{}

// Identity & Resources
func (f validationFactory) RequiredUserID() DomainError   { return f.req("user_id") }
func (f validationFactory) RequiredRoleID() DomainError   { return f.req("role_id") }
func (f validationFactory) RequiredDeviceID() DomainError { return f.req("device_id") }
func (f validationFactory) RequiredTokenID() DomainError  { return f.req("token_id") }

// Attributes & State
func (f validationFactory) RequiredEmail() DomainError    { return f.req("email") }
func (f validationFactory) RequiredPassword() DomainError { return f.req("password") }
func (f validationFactory) RequiredStatus() DomainError   { return f.req("status") }
func (f validationFactory) RequiredToken() DomainError    { return f.req("token") }
func (f validationFactory) RequiredName() DomainError     { return f.req("name") }

// Timestamps
func (f validationFactory) RequiredNow() DomainError { return f.req("now") }
func (f validationFactory) RequiredCreatedAt() DomainError {
	return f.msg("created_at", "missing timestamp")
}
func (f validationFactory) RequiredUpdatedAt() DomainError {
	return f.msg("updated_at", "missing timestamp")
}
func (f validationFactory) RequiredExpiresAt() DomainError {
	return f.msg("expires_at", "missing timestamp")
}

// Formats
func (f validationFactory) InvalidEmail() DomainError { return f.msg("email", "format is invalid") }

// Validation Helpers
func (validationFactory) req(key string) DomainError {
	return newErr(OpValidation, key, errors.New("required value is missing"))
}
func (validationFactory) msg(key, msg string) DomainError {
	return newErr(OpValidation, key, errors.New(msg))
}

// --- Violation Factory (Business Rules & Integrity) ---

var NewViolation = violationFactory{}

type violationFactory struct{}

// Chronology
func (f violationFactory) UpdatedBeforeCreated() DomainError {
	return f.rule("updated_at", "update timestamp cannot be earlier than creation")
}
func (f violationFactory) ExpirationInPast() DomainError {
	return f.rule("expires_at", "expiration date cannot be in the past")
}
func (f violationFactory) TokenExpired() DomainError {
	return f.rule("expires_at", "session has expired")
}

// User Lifecycle & Registration
func (f violationFactory) EmailAlreadyTaken() DomainError {
	return f.rule("email", "this email address is already registered")
}

// User Lifecycle
func (f violationFactory) UserDeleted() DomainError {
	return f.rule("status", "user account is deleted")
}
func (f violationFactory) UserAlreadyActive() DomainError {
	return f.rule("status", "user is already active")
}
func (f violationFactory) UserAlreadyInactive() DomainError {
	return f.rule("status", "user is already inactive")
}
func (f violationFactory) DeletedUserMustBeInactive() DomainError {
	return f.rule("status", "integrity error: deleted users must be set to inactive")
}

// Role Policy
func (f violationFactory) MinimumRoleRequired() DomainError {
	return f.rule("roles", "user must possess at least one role")
}
func (f violationFactory) RoleAlreadyAssigned() DomainError {
	return f.rule("roles", "role is already assigned to this user")
}
func (f violationFactory) RoleNotFound() DomainError {
	return f.rule("roles", "role not found on this user")
}
func (f violationFactory) RoleAlreadyExists() DomainError {
	return f.rule("role", "this role already exists in our records")
}

// Device Security & State
func (f violationFactory) DeviceRevoked() DomainError {
	return f.rule("status", "device access has been revoked")
}
func (f violationFactory) DeviceAlreadyActive() DomainError {
	return f.rule("is_active", "device is already active")
}
func (f violationFactory) DeviceAlreadyInactive() DomainError {
	return f.rule("is_active", "device is already inactive")
}
func (f violationFactory) DeviceDoesNotBelongToUser() DomainError {
	return f.rule("user_id", "security: this device is not registered to your account")
}

// Token Security & Persistence
func (f violationFactory) TokenDoesNotBelongToUser() DomainError {
	return f.rule("user_id", "security: this refresh token was not issued to your account")
}
func (f violationFactory) TokenDoesNotMatchDevice() DomainError {
	return f.rule("device_id", "security: token was issued for a different device")
}
func (f violationFactory) TokenRevoked() DomainError {
	return f.rule("status", "token is no longer valid")
}

// New methods added for RefreshTokenRepository
func (f violationFactory) TokenAlreadyExists() DomainError {
	return f.rule("refresh_token", "this token already exists in our records")
}
func (f violationFactory) TokenNotFound() DomainError {
	return newErr(OpNotFound, "refresh_token", errors.New("the requested refresh token could not be found"))
}

// Violation Helper
func (violationFactory) rule(key, msg string) DomainError {
	return newErr(OpRule, key, errors.New(msg))
}

// --- Internal Constructor ---

func newErr(op, key string, reason error) DomainError {
	return &domainError{op: op, key: key, reason: reason}
}
