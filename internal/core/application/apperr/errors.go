package apperr

import (
	"errors"
	"fmt"
	"go_auth/internal/core/domain/derr"
)

type AppErr interface {
	error
	Application()
}

// NotFoundErr represents a resource not found
type NotFoundErr struct {
	Resource string // e.g., "user"
	ID       string // optional identifier
}

func (e *NotFoundErr) Error() string {
	if e.ID != "" {
		return fmt.Sprintf("%s with ID %s not found", e.Resource, e.ID)
	}
	return fmt.Sprintf("%s not found", e.Resource)
}

func NewNotFoundErr(resource, id string) *NotFoundErr {
	return &NotFoundErr{
		Resource: resource,
		ID:       id,
	}
}

func (*NotFoundErr) Application() {}

// ConflictErr represents a business conflict (e.g., duplicate resource)
type ConflictErr struct {
	Resource string
	Reason   string // optional reason
}

func (e *ConflictErr) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("%s conflict: %s", e.Resource, e.Reason)
	}
	return fmt.Sprintf("%s conflict", e.Resource)
}
func NewConflictErr(resource, reason string) *ConflictErr {
	return &ConflictErr{
		Resource: resource,
		Reason:   reason,
	}
}

func (*ConflictErr) Application() {}

// AlreadyExistsErr is a special case of conflict when creating duplicate resources
type AlreadyExistsErr struct {
	Resource string
	ID       string
}

func (e *AlreadyExistsErr) Error() string {
	if e.ID != "" {
		return fmt.Sprintf("%s with ID %s already exists", e.Resource, e.ID)
	}
	return fmt.Sprintf("%s already exists", e.Resource)
}

func NewAlreadyExistsErr(resource, id string) *AlreadyExistsErr {
	return &AlreadyExistsErr{
		Resource: resource,
		ID:       id,
	}
}

func (*AlreadyExistsErr) Application() {}

// ValidationErr represents application-level validation errors
type ValidationErr struct {
	Cause error
}

func (e *ValidationErr) Error() string { return e.Cause.Error() }
func (*ValidationErr) Application()    {}

func NewValidationErr(err error) *ValidationErr {
	return &ValidationErr{Cause: err}
}

// Unauthorized error for login failures
type UnauthorizedErr struct {
	Reason string
}

func (e *UnauthorizedErr) Error() string { return e.Reason }
func (*UnauthorizedErr) Application()    {}

func NewUnauthorizedErr(reason string) *UnauthorizedErr {
	return &UnauthorizedErr{Reason: reason}
}

// Internal errors (e.g., infrastructure)
type InternalErr struct {
	Reason string
}

func (e *InternalErr) Error() string { return e.Reason }
func (*InternalErr) Application()    {}

func NewInternalErr(reason string) *InternalErr {
	return &InternalErr{Reason: reason}
}

// MapDomainErr converts domain errors into application errors
func MapDomainErr(err error) error {
	var vErr derr.ValidationErr
	if errors.As(err, &vErr) {
		return NewValidationErr(vErr)
	}
	return fmt.Errorf("domain error: %w", err)
}
