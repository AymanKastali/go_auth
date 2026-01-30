package domain

import "go_auth/internal/core/pkg/err"

// ---------------------------------------------------------
// Sentinel Registry
// ---------------------------------------------------------

var (
	// --- Identity Context ---
	ErrSessionNotFound   = err.New(err.CodeNotFound, "session was not found")
	ErrUserNotFound      = err.New(err.CodeNotFound, "user was not found")
	ErrUserIDRequired    = err.New(err.CodeValidation, "user identifier is required")
	ErrUserEmailRequired = err.New(err.CodeValidation, "user email address is required")
	ErrUserEmailInvalid  = err.New(err.CodeValidation, "user email format is invalid")
	ErrUserEmailTaken    = err.New(err.CodeConflict, "user email address is already in use")
	ErrUserDeleted       = err.New(err.CodeBusinessRule, "user was deleted")
	ErrUserInactive      = err.New(err.CodeBusinessRule, "user account is currently inactive")

	// --- Registration Policy Context ---
	// New: Business rules for account creation eligibility.
	ErrRegistrationDisabled = err.New(err.CodeForbidden, "public registration is currently disabled")
	ErrEmailDomainBlocked   = err.New(err.CodeForbidden, "the provided email domain is not permitted")

	// --- Credential Context ---
	ErrUserPasswordRequired = err.New(err.CodeValidation, "user password is required")
	ErrPasswordTooShort     = err.New(err.CodeValidation, "password length is below the minimum requirement")
	ErrPasswordTooLong      = err.New(err.CodeValidation, "password length exceeds the maximum limit")
	ErrPasswordNoUpper      = err.New(err.CodeValidation, "password must contain at least one uppercase letter")
	ErrPasswordNoNumber     = err.New(err.CodeValidation, "password must contain at least one numerical digit")
	ErrPasswordNoSpecial    = err.New(err.CodeValidation, "password must contain at least one special character")

	// --- Authentication & Authorization Context ---
	ErrAuthenticationFailed = err.New(err.CodeUnauthorized, "invalid email or password")
	ErrTokenInvalid         = err.New(err.CodeUnauthorized, "provided token is invalid or expired")
	ErrTokenRevoked         = err.New(err.CodeConflict, "token has been revoked")
	ErrRoleNotRecognized    = err.New(err.CodeValidation, "provided user role is not supported")

	// --- Session Context ---
	ErrSessionIDRequired      = err.New(err.CodeValidation, "session identifier is required")
	ErrSessionExpired         = err.New(err.CodeForbidden, "session has expired")
	ErrSessionAlreadyRevoked  = err.New(err.CodeConflict, "session is already in a revoked state")
	ErrSessionExpiryInPast    = err.New(err.CodeValidation, "session expiration cannot be set in the past")
	ErrSessionFingerprintMiss = err.New(err.CodeForbidden, "device fingerprint does not match the session")

	// --- Device & Metadata Context ---
	ErrDeviceIPRequired          = err.New(err.CodeValidation, "device IP address is required")
	ErrDeviceUARequired          = err.New(err.CodeValidation, "device user agent is required")
	ErrDeviceFingerprintRequired = err.New(err.CodeValidation, "device fingerprint is required")
	ErrAccessIdentityIncomplete  = err.New(err.CodeValidation, "access identity is missing required fields")

	// Internal Domain Error
	ErrInternal = err.New(err.CodeInternal, "internal domain failure")

	// --- Recovery Token Context ---
	ErrRecoveryTokenIDRequired = err.New(err.CodeValidation, "recovery token identifier is required")
	ErrRecoveryTokenRevoked    = err.New(err.CodeConflict, "recovery token has been revoked")
	ErrRecoveryTokenInvalid    = err.New(err.CodeUnauthorized, "recovery token is invalid or not found")
	ErrRecoveryTokenExpired    = err.New(err.CodeForbidden, "recovery token has expired")

	// This is the one the compiler is screaming about:
	// It triggers when a token is valid, but the UserID inside the token
	// doesn't match the User Aggregate we are trying to update.
	ErrInvalidRecoveryAttempt = err.New(err.CodeBusinessRule, "this recovery token does not belong to the specified user")

	// Optional but good for strictness:
	ErrRecoveryTokenAlreadyUsed = err.New(err.CodeConflict, "recovery token has already been consumed")
)
