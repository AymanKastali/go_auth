package derr

import (
	"errors"
	"fmt"
)

const opRule = "Business Rule"

type DomainError interface {
	error
	Domain()
}

var (
	errRequiredValue = errors.New("required value is missing")
	errInvalidValue  = errors.New("value violates domain rules")
	errUnknown       = errors.New("unknown domain violation")
)

type domainError struct {
	op     string
	key    string
	reason error
}

func (e *domainError) Error() string {
	// Ambiguity fix: include the 'key' in the string output
	return fmt.Sprintf("[Domain Error] %s: field '%s' - %v", e.op, e.key, e.reason)
}

func (e *domainError) Domain()       {}
func (e *domainError) Unwrap() error { return e.reason }

// NewRequiredValueErr handles cases where a mandatory field is empty or nil.
func NewRequiredValueErr(key string) DomainError {
	return &domainError{
		op:     opRule,
		key:    key,
		reason: errRequiredValue,
	}
}

// NewInvalidValueErr handles cases where data format or logic is rejected by the domain.
func NewInvalidValueErr(key string) DomainError {
	return &domainError{
		op:     opRule,
		key:    key,
		reason: errInvalidValue,
	}
}

////////////////////////////////

// ValidationError marks domain errors that are caused by invalid input
type ValidationErr interface {
	error
	Validation() // marker method
}

/*
Required attribute error
*/
type RequiredErr struct {
	Attr string
}

func (e *RequiredErr) Error() string {
	return fmt.Sprintf("%s is required", e.Attr)
}
func NewRequiredErr(attr string) *RequiredErr {
	return &RequiredErr{Attr: attr}
}

func (*RequiredErr) Domain()     {}
func (*RequiredErr) Validation() {}

/*
Invalid value error
*/
type InvalidValueErr struct {
	Attr   string
	Reason string
}

func (e *InvalidValueErr) Error() string {
	if e.Reason == "" {
		return fmt.Sprintf("%s has an invalid value", e.Attr)
	}
	return fmt.Sprintf("%s has an invalid value: %s", e.Attr, e.Reason)
}

// func NewInvalidValueErr(attr, reason string) *InvalidValueErr {
// 	return &InvalidValueErr{Attr: attr, Reason: reason}
// }

func (*InvalidValueErr) Domain()     {}
func (*InvalidValueErr) Validation() {}

/*
Domain rule violation
*/
type RuleViolationErr struct {
	Rule string
}

func (e *RuleViolationErr) Error() string {
	return e.Rule
}

func NewRuleViolationErr(rule string) *RuleViolationErr {
	return &RuleViolationErr{Rule: rule}
}

func (*RuleViolationErr) Domain() {}
