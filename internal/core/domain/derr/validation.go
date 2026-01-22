package derr

import "fmt"

// --- User & Role Identity Requirements ---

type ErrUserIDRequired struct{}

func NewErrUserIDRequired() *ErrUserIDRequired { return &ErrUserIDRequired{} }
func (e *ErrUserIDRequired) Error() string     { return "user identifier is required" }
func (e *ErrUserIDRequired) Code() ErrorCode   { return CodeValidation }

type ErrUserPasswordRequired struct{}

func NewErrUserPasswordRequired() *ErrUserPasswordRequired { return &ErrUserPasswordRequired{} }
func (e *ErrUserPasswordRequired) Error() string           { return "user password hash is required" }
func (e *ErrUserPasswordRequired) Code() ErrorCode         { return CodeValidation }

type ErrUserStatusRequired struct{}

func NewErrUserStatusRequired() *ErrUserStatusRequired { return &ErrUserStatusRequired{} }
func (e *ErrUserStatusRequired) Error() string         { return "user status is required" }
func (e *ErrUserStatusRequired) Code() ErrorCode       { return CodeValidation }

type ErrRoleIDRequired struct{}

func NewErrRoleIDRequired() *ErrRoleIDRequired { return &ErrRoleIDRequired{} }
func (e *ErrRoleIDRequired) Error() string     { return "role identifier is required" }
func (e *ErrRoleIDRequired) Code() ErrorCode   { return CodeValidation }

type ErrRoleNameRequired struct{}

func NewErrRoleNameRequired() *ErrRoleNameRequired { return &ErrRoleNameRequired{} }
func (e *ErrRoleNameRequired) Error() string       { return "role name is required" }
func (e *ErrRoleNameRequired) Code() ErrorCode     { return CodeValidation }

// --- Email & Credential Validation ---

type ErrEmailRequired struct{}

func NewErrEmailRequired() *ErrEmailRequired { return &ErrEmailRequired{} }
func (e *ErrEmailRequired) Error() string    { return "email is required" }
func (e *ErrEmailRequired) Code() ErrorCode  { return CodeValidation }

type ErrInvalidEmailFormat struct{}

func NewErrInvalidEmailFormat() *ErrInvalidEmailFormat { return &ErrInvalidEmailFormat{} }
func (e *ErrInvalidEmailFormat) Error() string         { return "invalid email format" }
func (e *ErrInvalidEmailFormat) Code() ErrorCode       { return CodeValidation }

type ErrPasswordRequired struct{}

func NewErrPasswordRequired() *ErrPasswordRequired { return &ErrPasswordRequired{} }
func (e *ErrPasswordRequired) Error() string       { return "password is required" }
func (e *ErrPasswordRequired) Code() ErrorCode     { return CodeValidation }

type ErrInvalidCredentials struct{}

func NewErrInvalidCredentials() *ErrInvalidCredentials { return &ErrInvalidCredentials{} }
func (e *ErrInvalidCredentials) Error() string         { return "invalid credentials" }
func (e *ErrInvalidCredentials) Code() ErrorCode       { return CodeValidation }

type ErrPasswordMismatch struct{}

func NewErrPasswordMismatch() *ErrPasswordMismatch { return &ErrPasswordMismatch{} }
func (e *ErrPasswordMismatch) Error() string       { return "password mismatch" }
func (e *ErrPasswordMismatch) Code() ErrorCode     { return CodeValidation }

// --- Password Policy ---

type ErrPasswordTooShort struct {
	MinLength uint8
}

func NewErrPasswordTooShort(min uint8) *ErrPasswordTooShort {
	return &ErrPasswordTooShort{MinLength: min}
}
func (e *ErrPasswordTooShort) Error() string {
	return fmt.Sprintf("password too short: minimum length %d", e.MinLength)
}
func (e *ErrPasswordTooShort) Code() ErrorCode { return CodeValidation }

type ErrPasswordTooWeak struct {
	Requirement string
}

func NewErrPasswordTooWeak(req string) *ErrPasswordTooWeak {
	return &ErrPasswordTooWeak{Requirement: req}
}
func (e *ErrPasswordTooWeak) Error() string {
	if e.Requirement != "" {
		return fmt.Sprintf("password too weak: missing %s", e.Requirement)
	}
	return "password too weak"
}
func (e *ErrPasswordTooWeak) Code() ErrorCode { return CodeValidation }

// --- Security & Device Requirements ---

type ErrRefreshTokenRequired struct{}

func NewErrRefreshTokenRequired() *ErrRefreshTokenRequired { return &ErrRefreshTokenRequired{} }
func (e *ErrRefreshTokenRequired) Error() string           { return "authentication token is required" }
func (e *ErrRefreshTokenRequired) Code() ErrorCode         { return CodeValidation }

type ErrRefreshTokenIDRequired struct{}

func NewErrRefreshTokenIDRequired() *ErrRefreshTokenIDRequired { return &ErrRefreshTokenIDRequired{} }
func (e *ErrRefreshTokenIDRequired) Error() string             { return "refresh token identifier is required" }
func (e *ErrRefreshTokenIDRequired) Code() ErrorCode           { return CodeValidation }

type ErrTokenHashRequired struct{}

func NewErrTokenHashRequired() *ErrTokenHashRequired {
	return &ErrTokenHashRequired{}
}
func (e *ErrTokenHashRequired) Error() string   { return "token hash is required" }
func (e *ErrTokenHashRequired) Code() ErrorCode { return CodeValidation }

type ErrInvalidRefreshTokenFormat struct{}

func NewErrInvalidRefreshTokenFormat() *ErrInvalidRefreshTokenFormat {
	return &ErrInvalidRefreshTokenFormat{}
}
func (e *ErrInvalidRefreshTokenFormat) Error() string   { return "invalid refresh token format" }
func (e *ErrInvalidRefreshTokenFormat) Code() ErrorCode { return CodeValidation }

type ErrDeviceIDRequired struct{}

func NewErrDeviceIDRequired() *ErrDeviceIDRequired { return &ErrDeviceIDRequired{} }
func (e *ErrDeviceIDRequired) Error() string {
	return "device identifier is required for security verification"
}
func (e *ErrDeviceIDRequired) Code() ErrorCode { return CodeValidation }

type ErrDeviceFingerprintRequired struct{}

func NewErrDeviceFingerprintRequired() *ErrDeviceFingerprintRequired {
	return &ErrDeviceFingerprintRequired{}
}
func (e *ErrDeviceFingerprintRequired) Error() string {
	return "device fingerprint is required for security verification"
}
func (e *ErrDeviceFingerprintRequired) Code() ErrorCode { return CodeValidation }

// --- Temporal & Logical Constraints ---

type ErrTimepointRequired struct{}

func NewErrTimepointRequired() *ErrTimepointRequired { return &ErrTimepointRequired{} }
func (e *ErrTimepointRequired) Error() string        { return "timestamp is required" }
func (e *ErrTimepointRequired) Code() ErrorCode      { return CodeValidation }

type ErrExpirationRequired struct{}

func NewErrExpirationRequired() *ErrExpirationRequired { return &ErrExpirationRequired{} }
func (e *ErrExpirationRequired) Error() string         { return "expiration time is required" }
func (e *ErrExpirationRequired) Code() ErrorCode       { return CodeValidation }

type ErrExpirationInPast struct{}

func NewErrExpirationInPast() *ErrExpirationInPast { return &ErrExpirationInPast{} }
func (e *ErrExpirationInPast) Error() string       { return "expiration time cannot be in the past" }
func (e *ErrExpirationInPast) Code() ErrorCode     { return CodeValidation }
