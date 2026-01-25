package domain

import "fmt"

type EntityName string

const (
	EntityUser    EntityName = "User"
	EntitySession EntityName = "Session"
)

type ErrorCode string

const (
	CodeValidation   ErrorCode = "VALIDATION_FAILED"
	CodeBusinessRule ErrorCode = "BUSINESS_RULE_VIOLATION"
	CodeConflict     ErrorCode = "CONFLICT"
	CodeNotFound     ErrorCode = "NOT_FOUND"
	CodeForbidden    ErrorCode = "FORBIDDEN"
	CodeUnauthorized ErrorCode = "UNAUTHORIZED"
	CodeInternal     ErrorCode = "INTERNAL"
)

type DomainError interface {
	error
	Code() ErrorCode
}

// CodeValidation
type ErrRequiredAttribute struct {
	Entity EntityName
	Field  string
}

func NewRequiredAttributeError(entity EntityName, field string) *ErrRequiredAttribute {
	return &ErrRequiredAttribute{}
}
func (e *ErrRequiredAttribute) Error() string {
	return fmt.Sprintf("%s.%s is required", e.Entity, e.Field)
}
func (e *ErrRequiredAttribute) Code() ErrorCode { return CodeValidation }

type ErrInvalidAttribute struct {
	Entity EntityName
	Field  string
}

func NewInvalidAttributeError(entity EntityName, field string) *ErrInvalidAttribute {
	return &ErrInvalidAttribute{}
}
func (e *ErrInvalidAttribute) Error() string {
	return fmt.Sprintf("%s.%s is invalid", e.Entity, e.Field)
}
func (e *ErrInvalidAttribute) Code() ErrorCode { return CodeValidation }

type ErrExpirationInPast struct{}

func NewExpirationInPastError() *ErrExpirationInPast { return &ErrExpirationInPast{} }
func (e *ErrExpirationInPast) Error() string         { return "expiration time cannot be in the past" }
func (e *ErrExpirationInPast) Code() ErrorCode       { return CodeValidation }

type ErrInvalidCredentials struct{}

func NewInvalidCredentialsError() *ErrInvalidCredentials { return &ErrInvalidCredentials{} }
func (e *ErrInvalidCredentials) Error() string           { return "invalid credentials" }
func (e *ErrInvalidCredentials) Code() ErrorCode         { return CodeValidation }

type ErrPasswordTooShort struct{ MinLength uint8 }

func NewPasswordTooShortError(min uint8) *ErrPasswordTooShort {
	return &ErrPasswordTooShort{MinLength: min}
}
func (e *ErrPasswordTooShort) Error() string {
	return fmt.Sprintf("password too short, minimum length %d", e.MinLength)
}
func (e *ErrPasswordTooShort) Code() ErrorCode { return CodeValidation }

type ErrPasswordTooLong struct{ MaxLength uint8 }

func NewPasswordTooLongError(min uint8) *ErrPasswordTooLong {
	return &ErrPasswordTooLong{MaxLength: min}
}
func (e *ErrPasswordTooLong) Error() string {
	return fmt.Sprintf("password too long, minimum length %d", e.MaxLength)
}
func (e *ErrPasswordTooLong) Code() ErrorCode { return CodeValidation }

type ErrPasswordMissingUppercase struct{}

func NewPasswordMissingUppercaseError() *ErrPasswordMissingUppercase {
	return &ErrPasswordMissingUppercase{}
}
func (e *ErrPasswordMissingUppercase) Error() string {
	return "password must contain at least one uppercase letter"
}
func (e *ErrPasswordMissingUppercase) Code() ErrorCode { return CodeValidation }

type ErrPasswordMissingNumber struct{}

func NewPasswordMissingNumberError() *ErrPasswordMissingNumber { return &ErrPasswordMissingNumber{} }
func (e *ErrPasswordMissingNumber) Error() string              { return "password must contain at least one number" }
func (e *ErrPasswordMissingNumber) Code() ErrorCode            { return CodeValidation }

type ErrPasswordMissingSpecialChar struct{}

func NewPasswordMissingSpecialCharError() *ErrPasswordMissingSpecialChar {
	return &ErrPasswordMissingSpecialChar{}
}
func (e *ErrPasswordMissingSpecialChar) Error() string {
	return "password must contain at least one special character (!@#$%^&*)"
}
func (e *ErrPasswordMissingSpecialChar) Code() ErrorCode { return CodeValidation }

type ErrInvalidRole struct{ RoleName string }

func NewInvalidRoleError(name string) *ErrInvalidRole {
	return &ErrInvalidRole{RoleName: name}
}
func (e *ErrInvalidRole) Error() string {
	return fmt.Sprintf("invalid role: %s", e.RoleName)
}
func (e *ErrInvalidRole) Code() ErrorCode { return CodeValidation }

// CodeConflict
type ErrUserAlreadyActive struct{ UserID string }

func NewUserAlreadyActiveError(userID string) *ErrUserAlreadyActive { return &ErrUserAlreadyActive{} }

func (e *ErrUserAlreadyActive) Error() string {
	return fmt.Sprintf("user %s is already active", e.UserID)
}
func (e *ErrUserAlreadyActive) Code() ErrorCode { return CodeConflict }

type ErrRoleAlreadyAssigned struct {
	RoleID string
	UserID string
}

func NewRoleAlreadyAssignedError(roleID, userID string) *ErrRoleAlreadyAssigned {
	return &ErrRoleAlreadyAssigned{RoleID: roleID, UserID: userID}
}

func (e *ErrRoleAlreadyAssigned) Error() string {
	return fmt.Sprintf("role '%s' has already been assigned to user '%s'", e.RoleID, e.UserID)
}

func (e *ErrRoleAlreadyAssigned) Code() ErrorCode { return CodeConflict }

type ErrTokenAlreadyRevoked struct{ TokenID string }

func NewTokenAlreadyRevokedError(tokenID string) *ErrTokenAlreadyRevoked {
	return &ErrTokenAlreadyRevoked{}
}

func (e *ErrTokenAlreadyRevoked) Error() string {
	return fmt.Sprintf("token %s is already revoked", e.TokenID)
}
func (e *ErrTokenAlreadyRevoked) Code() ErrorCode { return CodeConflict }

type ErrEmailAlreadyTaken struct{ Email string }

func NewEmailAlreadyTakenError(email string) *ErrEmailAlreadyTaken {
	return &ErrEmailAlreadyTaken{Email: email}
}

func (e *ErrEmailAlreadyTaken) Error() string {
	return fmt.Sprintf("email '%s' is already taken", e.Email)
}
func (e *ErrEmailAlreadyTaken) Code() ErrorCode { return CodeConflict }

// CodeBusinessRule
type ErrUserDeleted struct{ UserID string }

func NewUserDeletedError(userID string) *ErrUserDeleted { return &ErrUserDeleted{UserID: userID} }

func (e *ErrUserDeleted) Error() string   { return fmt.Sprintf("user %s is deleted", e.UserID) }
func (e *ErrUserDeleted) Code() ErrorCode { return CodeBusinessRule }

type ErrUserInactive struct{ UserID string }

func NewUserInactiveError(userID string) *ErrUserInactive { return &ErrUserInactive{UserID: userID} }

func (e *ErrUserInactive) Error() string { return fmt.Sprintf("user '%s' is inactive", e.UserID) }

func (e *ErrUserInactive) Code() ErrorCode { return CodeBusinessRule }

type ErrMinimumRolesRequired struct{ MinCount uint8 }

func NewMinimumRolesRequiredError() *ErrMinimumRolesRequired {
	return &ErrMinimumRolesRequired{MinCount: 1}
}

func (e *ErrMinimumRolesRequired) Error() string {
	return fmt.Sprintf("user must have at least %d role(s)", e.MinCount)
}
func (e *ErrMinimumRolesRequired) Code() ErrorCode { return CodeBusinessRule }

// CodeForbidden
type ErrSessionInvalid struct{ SessionID string }

func NewSessionInvalidError(sessionID string) *ErrSessionInvalid {
	return &ErrSessionInvalid{SessionID: sessionID}
}

func (e *ErrSessionInvalid) Error() string {
	return fmt.Sprintf("session %s is invalid", e.SessionID)
}
func (e *ErrSessionInvalid) Code() ErrorCode { return CodeForbidden }

type ErrSessionFingerprintMismatch struct{ SessionID string }

func NewSessionFingerprintMismatchError(sessionID string) *ErrSessionFingerprintMismatch {
	return &ErrSessionFingerprintMismatch{SessionID: sessionID}
}

func (e *ErrSessionFingerprintMismatch) Error() string {
	return fmt.Sprintf("session '%s' fingerprint mismatch", e.SessionID)
}
func (e *ErrSessionFingerprintMismatch) Code() ErrorCode { return CodeForbidden }

// CodeNotFound
type ErrSessionNotFound struct{ SessionID string }

func NewSessionNotFoundError(sessionID string) error { return ErrSessionNotFound{SessionID: sessionID} }

func (e ErrSessionNotFound) Error() string {
	return fmt.Sprintf("session with id %s was not found for this user", e.SessionID)
}
func (e *ErrSessionNotFound) Code() ErrorCode { return CodeNotFound }

type ErrUserNotFound struct{ UserID string }

func NewUserNotFoundError(userID string) error { return ErrUserNotFound{UserID: userID} }

func (e ErrUserNotFound) Error() string {
	return fmt.Sprintf("user with id %s was not found", e.UserID)
}
func (e *ErrUserNotFound) Code() ErrorCode { return CodeNotFound }

// CodeInternal
type ErrInternal struct {
	Message string
	Cause   error
}

func NewInternalError(msg string, cause error) *ErrInternal {
	return &ErrInternal{Message: msg, Cause: cause}
}
func (e *ErrInternal) Error() string   { return fmt.Sprintf("internal system error: %s", e.Message) }
func (e *ErrInternal) Code() ErrorCode { return CodeInternal }

// CodeUnauthorized
type ErrInvalidIdentity struct{ Reason string }

func NewInvalidIdentityError(reason string) *ErrInvalidIdentity {
	return &ErrInvalidIdentity{Reason: reason}
}
func (e *ErrInvalidIdentity) Error() string   { return fmt.Sprintf("identity invalid: %s", e.Reason) }
func (e *ErrInvalidIdentity) Code() ErrorCode { return CodeUnauthorized }
