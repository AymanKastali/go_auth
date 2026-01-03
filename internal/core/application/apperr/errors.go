package apperr

import (
	"errors"
	"go_auth/internal/core/domain/domainerr"
)

type code uint16

const (
	CodeInternal      code = iota // 0
	CodeInvalidInput              // 1
	CodeNotFound                  // 2
	CodeConflict                  // 3
	CodeUnauthorized              // 4
	CodeUnprocessable             // 5
)

type AppError struct {
	code    code
	message string
	field   string
}

func (e *AppError) Error() string { return e.message }
func (e *AppError) Code() code    { return e.code }
func (e *AppError) Field() string { return e.field }

// --- Factories (Standardized Constructors like Domain) ---

func NewInternal(msg string) error {
	return &AppError{code: CodeInternal, message: msg}
}

func NewNotFound(msg string) error {
	return &AppError{code: CodeNotFound, message: msg}
}

func NewConflict(msg string) error {
	return &AppError{code: CodeConflict, message: msg}
}

func NewUnauthorized(msg string) error {
	return &AppError{code: CodeUnauthorized, message: msg}
}

func NewInvalidInput(msg string, field string) error {
	return &AppError{code: CodeInvalidInput, message: msg, field: field}
}

// MapDomain converts Domain logic into Application context
func MapDomain(err error) error {
	if err == nil {
		return nil
	}

	var dErr domainerr.DomainError
	if errors.As(err, &dErr) {
		code := CodeInvalidInput
		if dErr.Code() == domainerr.CodeRuleViolation {
			code = CodeUnprocessable
		}

		return &AppError{
			code:    code,
			message: dErr.Error(),
			field:   dErr.Attr(),
		}
	}

	// Any unknown error becomes a secure Internal error
	return NewInternal("an unexpected error occurred")
}
