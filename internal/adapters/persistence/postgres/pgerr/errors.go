package pgerr

import (
	"errors"
	"fmt"
)

// PostgresErr interface ensures all DB errors have common markers.
type PostgresErr interface {
	error
	Adapters()
}

// --- Private Sentinels (The "What") ---
var (
	errDataCorruption = errors.New("data inconsistency detected")
	errMigration      = errors.New("migration failed")
	errConnFailure    = errors.New("connection establishment failed")
	errUnknown        = errors.New("unknown error cause")
)

// --- Private Implementation (The "Where") ---
type postgresErr struct {
	op     string
	entity string
	id     string
	reason error
}

func (e *postgresErr) Error() string {
	if e.entity != "" {
		return fmt.Sprintf("[Postgres Corruption] %s[%s]: %v", e.entity, e.id, e.reason)
	}
	return fmt.Sprintf("[Postgres Error] %s: %v", e.op, e.reason)
}

func (e *postgresErr) Adapters()     {}
func (e *postgresErr) Unwrap() error { return e.reason }

// --- New Methods (The "How" - Returning the Interface) ---

func NewDataCorruptionErr(entity, id string, err error) PostgresErr {
	cause := err
	if cause == nil {
		cause = errUnknown
	}

	return &postgresErr{
		entity: entity,
		id:     id,
		reason: errors.Join(errDataCorruption, cause),
	}
}

func NewMigrationErr(err error) PostgresErr {
	cause := err
	if cause == nil {
		cause = errUnknown
	}

	return &postgresErr{
		op:     "Schema Migration",
		reason: errors.Join(errMigration, cause),
	}
}

func NewConnErr(err error) PostgresErr {
	cause := err
	if cause == nil {
		cause = errUnknown
	}
	return &postgresErr{
		op:     "Connection",
		reason: errors.Join(errConnFailure, err),
	}
}
