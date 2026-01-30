package domain

// ---------------------------------------------------------
// Error Infrastructure
// ---------------------------------------------------------

type Code string

const (
	CodeValidation   Code = "VALIDATION_FAILED"
	CodeConflict     Code = "CONFLICT"
	CodeNotFound     Code = "NOT_FOUND"
	CodeBusinessRule Code = "BUSINESS_RULE_VIOLATION"
	CodeUnauthorized Code = "UNAUTHORIZED"
	CodeForbidden    Code = "FORBIDDEN"
	CodeInternal     Code = "INTERNAL"
)

type Error struct {
	code    Code
	message string
}

func (e *Error) Error() string   { return e.message }
func (e *Error) Code() Code      { return e.code }
func (e *Error) Message() string { return e.message }

func NewError(code Code, msg string) error { return &Error{code: code, message: msg} }

// ---------------------------------------------------------
// Sentinel Registry
// ---------------------------------------------------------

var (
	// --- Identity Context ---
	ErrSessionNotFound   = NewError(CodeNotFound, "session was not found")
	ErrUserNotFound      = NewError(CodeNotFound, "user was not found")
	ErrUserIDRequired    = NewError(CodeValidation, "user identifier is required")
	ErrUserEmailRequired = NewError(CodeValidation, "user email address is required")
	ErrUserEmailInvalid  = NewError(CodeValidation, "user email format is invalid")
	ErrUserEmailTaken    = NewError(CodeConflict, "user email address is already in use")
	ErrUserDeleted       = NewError(CodeBusinessRule, "user was deleted")
	ErrUserInactive      = NewError(CodeBusinessRule, "user account is currently inactive")

	// --- Registration Policy Context ---
	ErrRegistrationDisabled = NewError(CodeForbidden, "public registration is currently disabled")
	ErrEmailDomainBlocked   = NewError(CodeForbidden, "the provided email domain is not permitted")

	// --- Credential Context ---
	ErrUserPasswordRequired = NewError(CodeValidation, "user password is required")
	ErrPasswordTooShort     = NewError(CodeValidation, "password length is below the minimum requirement")
	ErrPasswordTooLong      = NewError(CodeValidation, "password length exceeds the maximum limit")
	ErrPasswordNoUpper      = NewError(CodeValidation, "password must contain at least one uppercase letter")
	ErrPasswordNoNumber     = NewError(CodeValidation, "password must contain at least one numerical digit")
	ErrPasswordNoSpecial    = NewError(CodeValidation, "password must contain at least one special character")

	// --- Authentication & Authorization Context ---
	ErrAuthenticationFailed = NewError(CodeUnauthorized, "invalid email or password")
	ErrTokenInvalid         = NewError(CodeUnauthorized, "provided token is invalid or expired")
	ErrTokenRevoked         = NewError(CodeConflict, "token has been revoked")
	ErrRoleNotRecognized    = NewError(CodeValidation, "provided user role is not supported")

	// --- Session Context ---
	ErrSessionIDRequired      = NewError(CodeValidation, "session identifier is required")
	ErrSessionExpired         = NewError(CodeForbidden, "session has expired")
	ErrSessionAlreadyRevoked  = NewError(CodeConflict, "session is already in a revoked state")
	ErrSessionExpiryInPast    = NewError(CodeValidation, "session expiration cannot be set in the past")
	ErrSessionFingerprintMiss = NewError(CodeForbidden, "device fingerprint does not match the session")

	// --- Device & Metadata Context ---
	ErrDeviceIPRequired          = NewError(CodeValidation, "device IP address is required")
	ErrDeviceUARequired          = NewError(CodeValidation, "device user agent is required")
	ErrDeviceFingerprintRequired = NewError(CodeValidation, "device fingerprint is required")
	ErrAccessIdentityIncomplete  = NewError(CodeValidation, "access identity is missing required fields")

	// Internal Domain Error
	ErrInternal = NewError(CodeInternal, "internal domain failure")

	// --- Recovery Token Context ---
	ErrRecoveryTokenIDRequired = NewError(CodeValidation, "recovery token identifier is required")
	ErrRecoveryTokenRevoked    = NewError(CodeConflict, "recovery token has been revoked")
	ErrRecoveryTokenInvalid    = NewError(CodeUnauthorized, "recovery token is invalid or not found")
	ErrRecoveryTokenExpired    = NewError(CodeForbidden, "recovery token has expired")

	// This triggers when a token is valid, but the UserID inside the token
	// doesn't match the User Aggregate we are trying to update.
	ErrInvalidRecoveryAttempt = NewError(CodeBusinessRule, "this recovery token does not belong to the specified user")

	ErrRecoveryTokenAlreadyUsed = NewError(CodeConflict, "recovery token has already been consumed")
)
