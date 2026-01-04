package derr

import "fmt"

/*
Domain error marker
*/
type DomainErr interface {
	error
	Domain()
}

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

func NewInvalidValueErr(attr, reason string) *InvalidValueErr {
	return &InvalidValueErr{Attr: attr, Reason: reason}
}

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

// var dErr domain.DomainErr
// if errors.As(err, &dErr) {
// 	// This error came from the domain layer
// }
