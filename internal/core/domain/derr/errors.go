package derr

import (
	"fmt"
)

type Code int

const (
	CodeUnknown          Code = iota // 0
	CodeNotFound                     // 1
	CodeValidation                   // 2
	CodeConflict                     // 3
	CodePermissionDenied             // 4
	CodeInternal                     // 5
)

type DomainError interface {
	error
	Code() Code
}

type domainError struct {
	code    Code
	message string
}

var _ DomainError = (*domainError)(nil)

func (e *domainError) Error() string { return e.message }
func (e *domainError) Code() Code    { return e.code }

func ErrRequired(attr string) DomainError {
	return newErr(CodeValidation, fmt.Sprintf("'%s' is required", attr))
}

func ErrInvalid(attr string) DomainError {
	return newErr(CodeValidation, fmt.Sprintf("'%s' is invalid", attr))
}

func ErrExpirationDateCannotBePast() DomainError {
	return newErr(CodeValidation, "expiration date cannot be in the past")
}

func ErrMinimumRequirement(attr string, minimum int) DomainError {
	return newErr(CodeValidation, fmt.Sprintf("'%s' must be at least %d", attr, minimum))
}

func ErrNotFound(entity, value string) DomainError {
	return newErr(CodeNotFound, fmt.Sprintf("%s '%s' not found", entity, value))
}

func ErrDuplicate(attribute, value string) DomainError {
	return newErr(CodeConflict, fmt.Sprintf("%s '%s' is already assigned", attribute, value))
}

func ErrEntityRevoked(entity string) DomainError {
	return newErr(CodeConflict, fmt.Sprintf("'%s' is revoked", entity))
}

func ErrEntityDeleted(entity string) DomainError {
	return newErr(CodeConflict, fmt.Sprintf("'%s' is deleted", entity))
}

func ErrStatusAlready(entity, status string) DomainError {
	return newErr(CodeConflict, fmt.Sprintf("'%s' is already '%s'", entity, status))
}

func ErrExpired(entity string) DomainError {
	return newErr(CodeConflict, fmt.Sprintf("entity '%s' is expired", entity))
}

func ErrOwnershipViolation(entity, owner string) DomainError {
	return newErr(CodePermissionDenied, fmt.Sprintf("'%s' does not belong to the expected '%s'", entity, owner))
}

func newErr(code Code, msg string) DomainError {
	return &domainError{
		code:    code,
		message: fmt.Sprintf("[Domain Error]: %s", msg),
	}
}
