package domainerr

import (
	"fmt"
	"strings"
)

type Code uint16

const (
	CodeRequiredAttr    Code = 1001
	CodeInvalidValue    Code = 1002
	CodeInvalidState    Code = 1003
	CodeOperationDenied Code = 1004
)

type DomainError struct {
	code    Code
	message string
	op      string
	cause   error
}

func (e *DomainError) Code() Code      { return e.code }
func (e *DomainError) Message() string { return e.message }
func (e *DomainError) Op() string      { return e.op }
func (e *DomainError) Cause() error    { return e.cause }

func newDomainError(code Code, op, msg string, cause error) *DomainError {
	return &DomainError{
		code:    code,
		op:      op,
		message: msg,
		cause:   cause,
	}
}

func RequiredAttrError(attr, op string) *DomainError {
	return newDomainError(
		CodeRequiredAttr,
		op,
		fmt.Sprintf("%s is required", attr),
		nil,
	)
}

func RequiredAttrsError(attrs []string, op string) *DomainError {
	if len(attrs) == 0 {
		panic("RequiredAttrs called with empty attrs")
	}

	verb := "are"
	if len(attrs) == 1 {
		verb = "is"
	}

	return newDomainError(
		CodeRequiredAttr,
		op,
		fmt.Sprintf("%s %s required", strings.Join(attrs, ", "), verb),
		nil,
	)
}

func InvalidValueError(attr, op string, cause error) *DomainError {
	return newDomainError(
		CodeInvalidValue,
		op,
		fmt.Sprintf("%s is invalid", attr),
		cause,
	)
}

func InvalidStateError(msg, op string) *DomainError {
	return newDomainError(
		CodeInvalidState,
		op,
		msg,
		nil,
	)
}

func OperationDeniedError(msg, op string) *DomainError {
	return newDomainError(
		CodeOperationDenied,
		op,
		msg,
		nil,
	)
}

func (e *DomainError) Error() string {
	if e.cause != nil {
		return fmt.Sprintf(
			"[domain:%s] %d %s: %v",
			e.op,
			e.code,
			e.message,
			e.cause,
		)
	}

	return fmt.Sprintf(
		"[domain:%s] %d %s",
		e.op,
		e.code,
		e.message,
	)
}

func (e *DomainError) Unwrap() error {
	return e.cause
}
