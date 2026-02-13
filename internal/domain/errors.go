package domain

// ---------------------------------------------------------
// Error Infrastructure
// ---------------------------------------------------------

type Kind string

const (
	KindValidation   Kind = "VALIDATION_FAILED"
	KindConflict     Kind = "CONFLICT"
	KindNotFound     Kind = "NOT_FOUND"
	KindBusinessRule Kind = "BUSINESS_RULE_VIOLATION"
	KindUnauthorized Kind = "UNAUTHORIZED"
	KindForbidden    Kind = "FORBIDDEN"
	KindInternal     Kind = "INTERNAL"
)

type Error struct {
	kind    Kind
	message string
}

func (e *Error) Error() string   { return e.message }
func (e *Error) Kind() Kind      { return e.kind }
func (e *Error) Message() string { return e.message }

func NewError(kind Kind, msg string) error { return &Error{kind: kind, message: msg} }

// ---------------------------------------------------------
// Sentinel Registry
// ---------------------------------------------------------

var (
	// --- Identity Context ---
	ErrSessionNotFound   = NewError(KindNotFound, "session was not found")
	ErrUserNotFound      = NewError(KindNotFound, "user was not found")
	ErrUserIDRequired    = NewError(KindValidation, "user identifier is required")
	ErrUserEmailRequired = NewError(KindValidation, "user email address is required")
	ErrUserEmailInvalid  = NewError(KindValidation, "user email format is invalid")
	ErrUserEmailTaken    = NewError(KindConflict, "user email address is already in use")
	ErrUserDeleted       = NewError(KindBusinessRule, "user was deleted")
	ErrUserInactive      = NewError(KindBusinessRule, "user account is currently inactive")

	// --- Registration Policy Context ---
	ErrRegistrationDisabled = NewError(KindForbidden, "public registration is currently disabled")
	ErrEmailDomainBlocked   = NewError(KindForbidden, "the provided email domain is not permitted")

	// --- Credential Context ---
	ErrUserPasswordRequired = NewError(KindValidation, "user password is required")
	ErrPasswordTooShort     = NewError(KindValidation, "password length is below the minimum requirement")
	ErrPasswordTooLong      = NewError(KindValidation, "password length exceeds the maximum limit")
	ErrPasswordNoUpper      = NewError(KindValidation, "password must contain at least one uppercase letter")
	ErrPasswordNoNumber     = NewError(KindValidation, "password must contain at least one numerical digit")
	ErrPasswordNoSpecial    = NewError(KindValidation, "password must contain at least one special character")

	// --- Authentication & Authorization Context ---
	ErrAuthenticationFailed = NewError(KindUnauthorized, "invalid email or password")
	ErrTokenInvalid         = NewError(KindUnauthorized, "provided token is invalid or expired")
	ErrTokenRevoked         = NewError(KindConflict, "token has been revoked")
	ErrRoleNotRecognized    = NewError(KindValidation, "role name is required")
	ErrRoleNameInvalid      = NewError(KindValidation, "role name must be 2-50 lowercase letters, digits, or underscores, starting with a letter")
	ErrRoleIDRequired       = NewError(KindValidation, "role identifier is required")
	ErrRoleAlreadyExists    = NewError(KindConflict, "role with this name already exists")
	ErrRoleNotFound         = NewError(KindNotFound, "role was not found")
	ErrRoleNotAssigned      = NewError(KindNotFound, "role is not assigned to this user")
	ErrPermissionInvalid    = NewError(KindValidation, "permission must be in 'resource:action' format")
	ErrPermissionNotFound   = NewError(KindNotFound, "permission was not found on this role")
	ErrForbiddenRole        = NewError(KindForbidden, "insufficient role permissions for this action")

	// --- Session Context ---
	ErrSessionUserIDRequired  = NewError(KindValidation, "session user identifier is required")
	ErrSessionIDRequired      = NewError(KindValidation, "session identifier is required")
	ErrSessionExpired         = NewError(KindForbidden, "session has expired")
	ErrSessionAlreadyRevoked  = NewError(KindConflict, "session is already in a revoked state")
	ErrSessionExpiryInPast    = NewError(KindValidation, "session expiration cannot be set in the past")
	ErrSessionExpiryInvalid   = NewError(KindValidation, "session expiry must be in the future")
	ErrSessionFingerprintMiss = NewError(KindForbidden, "device fingerprint does not match the session")
	ErrSessionTokenReuse      = NewError(KindForbidden, "refresh token reuse detected; session revoked")

	// --- Device & Metadata Context ---
	ErrDeviceIPRequired          = NewError(KindValidation, "device IP address is required")
	ErrDeviceUARequired          = NewError(KindValidation, "device user agent is required")
	ErrDeviceFingerprintRequired = NewError(KindValidation, "device fingerprint is required")
	ErrAccessIdentityIncomplete  = NewError(KindValidation, "access identity is missing required fields")

	// Internal Domain Error
	ErrInternal = NewError(KindInternal, "internal domain failure")

	// --- Recovery Token Context ---
	ErrRecoveryTokenIDRequired = NewError(KindValidation, "recovery token identifier is required")
	ErrRecoveryTokenRevoked    = NewError(KindConflict, "recovery token has been revoked")
	ErrRecoveryTokenInvalid    = NewError(KindUnauthorized, "recovery token is invalid or not found")
	ErrRecoveryTokenExpired    = NewError(KindForbidden, "recovery token has expired")

	// This triggers when a token is valid, but the UserID inside the token
	// doesn't match the User Aggregate we are trying to update.
	ErrInvalidRecoveryAttempt = NewError(KindBusinessRule, "this recovery token does not belong to the specified user")

	ErrRecoveryTokenAlreadyUsed = NewError(KindConflict, "recovery token has already been consumed")

	// --- Activation Token Context ---
	ErrActivationTokenIDRequired  = NewError(KindValidation, "activation token identifier is required")
	ErrActivationTokenInvalid     = NewError(KindUnauthorized, "activation token is invalid or not found")
	ErrActivationTokenExpired     = NewError(KindForbidden, "activation token has expired")
	ErrActivationTokenAlreadyUsed = NewError(KindConflict, "activation token has already been consumed")
	ErrUserAlreadyActive          = NewError(KindConflict, "user account is already active")
)
