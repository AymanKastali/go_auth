package pgerr

import (
	"errors"
	"fmt"
)

type repoError struct {
	inner         error
	msg           string
	isConflict    bool
	isNotFound    bool
	isUnavailable bool // Changed from isConn to match the factory name
	isInternal    bool
}

func (e *repoError) Error() string {
	if e.inner != nil {
		return fmt.Sprintf("%s: %v", e.msg, e.inner)
	}
	return e.msg
}

func (e *repoError) Unwrap() error { return e.inner }

// --- Behavior Checkers ---

func IsAlreadyExists(err error) bool {
	var re *repoError
	return errors.As(err, &re) && re.isConflict
}

func IsNotFound(err error) bool {
	var re *repoError
	return errors.As(err, &re) && re.isNotFound
}

func IsUnavailable(err error) bool {
	var re *repoError
	return errors.As(err, &re) && re.isUnavailable
}

// --- Factory Methods ---

func WrapAlreadyExists(err error, msg string) error {
	return &repoError{inner: err, msg: msg, isConflict: true}
}

func WrapNotFound(err error, msg string) error {
	return &repoError{inner: err, msg: msg, isNotFound: true}
}

// This matches your Repository calls
func WrapUnavailable(err error, msg string) error {
	return &repoError{inner: err, msg: msg, isUnavailable: true}
}

func WrapInternal(err error, msg string) error {
	return &repoError{inner: err, msg: msg, isInternal: true}
}
