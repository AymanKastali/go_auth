package domainerr

import (
	"fmt"
)

type Code uint16

const (
	CodeInternal      Code = iota // 0
	CodeRequired                  // 1
	CodeInvalidValue              // 2
	CodeRuleViolation             // 3
)

type DomainError interface {
	error
	Code() Code
	Attr() string // The specific field (e.g., "email")
}

type domainErr struct {
	code Code
	attr string
	msg  string
}

func (e *domainErr) Error() string { return e.msg }
func (e *domainErr) Code() Code    { return e.code }
func (e *domainErr) Attr() string  { return e.attr }

// Factories - Standardized constructors
func NewRequired(attr string) error {
	return &domainErr{code: CodeRequired, attr: attr, msg: fmt.Sprintf("%s is required", attr)}
}

func NewInvalidValue(attr, msg string) error {
	return &domainErr{code: CodeInvalidValue, attr: attr, msg: msg}
}

func NewRuleViolation(msg string) error {
	return &domainErr{code: CodeRuleViolation, msg: msg}
}
