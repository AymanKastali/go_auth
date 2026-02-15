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
	code    string
	message string
}

func (e *Error) Error() string   { return e.message }
func (e *Error) Kind() Kind      { return e.kind }
func (e *Error) Code() string    { return e.code }
func (e *Error) Message() string { return e.message }

func NewError(kind Kind, code, msg string) error {
	return &Error{kind: kind, code: code, message: msg}
}

// ---------------------------------------------------------
// Sentinel Registry
// ---------------------------------------------------------

var (
	// --- Identity Context ---
	ErrSessionNotFound   = NewError(KindNotFound, "SESSION_NOT_FOUND", "session was not found")
	ErrUserNotFound      = NewError(KindNotFound, "USER_NOT_FOUND", "user was not found")
	ErrUserIDRequired    = NewError(KindValidation, "USER_ID_REQUIRED", "user identifier is required")
	ErrUserEmailRequired = NewError(KindValidation, "USER_EMAIL_REQUIRED", "user email address is required")
	ErrUserEmailInvalid  = NewError(KindValidation, "USER_EMAIL_INVALID", "user email format is invalid")
	ErrUserEmailTaken    = NewError(KindConflict, "EMAIL_TAKEN", "user email address is already in use")
	ErrUserDeleted       = NewError(KindBusinessRule, "USER_DELETED", "user was deleted")
	ErrUserInactive      = NewError(KindBusinessRule, "USER_INACTIVE", "user account is currently inactive")

	// --- Registration Policy Context ---
	ErrRegistrationDisabled = NewError(KindForbidden, "REGISTRATION_DISABLED", "public registration is currently disabled")
	ErrEmailDomainBlocked   = NewError(KindForbidden, "EMAIL_DOMAIN_BLOCKED", "the provided email domain is not permitted")

	// --- Credential Context ---
	ErrUserPasswordRequired = NewError(KindValidation, "PASSWORD_REQUIRED", "user password is required")
	ErrPasswordTooShort     = NewError(KindValidation, "PASSWORD_TOO_SHORT", "password length is below the minimum requirement")
	ErrPasswordTooLong      = NewError(KindValidation, "PASSWORD_TOO_LONG", "password length exceeds the maximum limit")
	ErrPasswordNoUpper      = NewError(KindValidation, "PASSWORD_NO_UPPER", "password must contain at least one uppercase letter")
	ErrPasswordNoNumber     = NewError(KindValidation, "PASSWORD_NO_NUMBER", "password must contain at least one numerical digit")
	ErrPasswordNoSpecial    = NewError(KindValidation, "PASSWORD_NO_SPECIAL", "password must contain at least one special character")

	// --- Authentication & Authorization Context ---
	ErrAuthenticationFailed = NewError(KindUnauthorized, "AUTHENTICATION_FAILED", "invalid email or password")
	ErrTokenInvalid         = NewError(KindUnauthorized, "TOKEN_INVALID", "provided token is invalid or expired")
	ErrTokenRevoked         = NewError(KindConflict, "TOKEN_REVOKED", "token has been revoked")
	ErrRoleNotRecognized    = NewError(KindValidation, "ROLE_NAME_REQUIRED", "role name is required")
	ErrRoleNameInvalid      = NewError(KindValidation, "ROLE_NAME_INVALID", "role name must be 2-50 lowercase letters, digits, or underscores, starting with a letter")
	ErrRoleIDRequired       = NewError(KindValidation, "ROLE_ID_REQUIRED", "role identifier is required")
	ErrRoleAlreadyExists    = NewError(KindConflict, "ROLE_ALREADY_EXISTS", "role with this name already exists")
	ErrRoleNotFound         = NewError(KindNotFound, "ROLE_NOT_FOUND", "role was not found")
	ErrRoleNotAssigned      = NewError(KindNotFound, "ROLE_NOT_ASSIGNED", "role is not assigned to this user")
	ErrPermissionInvalid    = NewError(KindValidation, "PERMISSION_INVALID", "permission must be in 'resource:action' format")
	ErrPermissionNotFound   = NewError(KindNotFound, "PERMISSION_NOT_FOUND", "permission was not found on this role")
	ErrForbiddenRole        = NewError(KindForbidden, "INSUFFICIENT_ROLE", "insufficient role permissions for this action")

	// --- Session Context ---
	ErrSessionUserIDRequired  = NewError(KindValidation, "SESSION_USER_ID_REQUIRED", "session user identifier is required")
	ErrSessionIDRequired      = NewError(KindValidation, "SESSION_ID_REQUIRED", "session identifier is required")
	ErrSessionExpired         = NewError(KindForbidden, "SESSION_EXPIRED", "session has expired")
	ErrSessionAlreadyRevoked  = NewError(KindConflict, "SESSION_ALREADY_REVOKED", "session is already in a revoked state")
	ErrSessionExpiryInPast    = NewError(KindValidation, "SESSION_EXPIRY_IN_PAST", "session expiration cannot be set in the past")
	ErrSessionExpiryInvalid   = NewError(KindValidation, "SESSION_EXPIRY_INVALID", "session expiry must be in the future")
	ErrSessionFingerprintMiss = NewError(KindForbidden, "SESSION_FINGERPRINT_MISMATCH", "device fingerprint does not match the session")
	ErrSessionTokenReuse      = NewError(KindForbidden, "SESSION_TOKEN_REUSE", "refresh token reuse detected; session revoked")

	// --- Device & Metadata Context ---
	ErrDeviceIPRequired          = NewError(KindValidation, "DEVICE_IP_REQUIRED", "device IP address is required")
	ErrDeviceUARequired          = NewError(KindValidation, "DEVICE_UA_REQUIRED", "device user agent is required")
	ErrDeviceFingerprintRequired = NewError(KindValidation, "DEVICE_FINGERPRINT_REQUIRED", "device fingerprint is required")
	ErrAccessIdentityIncomplete  = NewError(KindValidation, "ACCESS_IDENTITY_INCOMPLETE", "access identity is missing required fields")

	// Internal Domain Error
	ErrInternal = NewError(KindInternal, "INTERNAL_ERROR", "internal domain failure")

	// --- Recovery Token Context ---
	ErrRecoveryTokenIDRequired = NewError(KindValidation, "RECOVERY_TOKEN_ID_REQUIRED", "recovery token identifier is required")
	ErrRecoveryTokenRevoked    = NewError(KindConflict, "RECOVERY_TOKEN_REVOKED", "recovery token has been revoked")
	ErrRecoveryTokenInvalid    = NewError(KindUnauthorized, "RECOVERY_TOKEN_INVALID", "recovery token is invalid or not found")
	ErrRecoveryTokenExpired    = NewError(KindForbidden, "RECOVERY_TOKEN_EXPIRED", "recovery token has expired")

	// This triggers when a token is valid, but the UserID inside the token
	// doesn't match the User Aggregate we are trying to update.
	ErrInvalidRecoveryAttempt = NewError(KindBusinessRule, "INVALID_RECOVERY_ATTEMPT", "this recovery token does not belong to the specified user")

	ErrRecoveryTokenAlreadyUsed = NewError(KindConflict, "RECOVERY_TOKEN_ALREADY_USED", "recovery token has already been consumed")

	// --- Account Lockout Context ---
	ErrAccountLocked = NewError(KindForbidden, "ACCOUNT_LOCKED", "account is temporarily locked due to too many failed login attempts")

	// --- Token Expiry Context ---
	ErrTokenExpiryInPast = NewError(KindValidation, "TOKEN_EXPIRY_IN_PAST", "token expiration cannot be set in the past")

	// --- Activation Token Context ---
	ErrActivationTokenIDRequired  = NewError(KindValidation, "ACTIVATION_TOKEN_ID_REQUIRED", "activation token identifier is required")
	ErrActivationTokenInvalid     = NewError(KindUnauthorized, "ACTIVATION_TOKEN_INVALID", "activation token is invalid or not found")
	ErrActivationTokenExpired     = NewError(KindForbidden, "ACTIVATION_TOKEN_EXPIRED", "activation token has expired")
	ErrActivationTokenAlreadyUsed = NewError(KindConflict, "ACTIVATION_TOKEN_ALREADY_USED", "activation token has already been consumed")
	ErrUserAlreadyActive          = NewError(KindConflict, "USER_ALREADY_ACTIVE", "user account is already active")
)
