package pgerr

import (
	"fmt"
)

type PostgresErr interface {
	error
	Persistence()
}

type DataCorruptionErr struct {
	Entity string
	ID     string
	Field  string
	Cause  error
}

func (e *DataCorruptionErr) Error() string {
	return fmt.Sprintf("data corruption in %s [%s] at field '%s': %v", e.Entity, e.ID, e.Field, e.Cause)
}

func (*DataCorruptionErr) Persistence() {}

func NewDataCorruptionErr(entity, id, field string, err error) *DataCorruptionErr {
	return &DataCorruptionErr{
		Entity: entity,
		ID:     id,
		Field:  field,
		Cause:  err,
	}
}

// InternalDBErr represents raw Postgres/GORM failures (Connection, Timeout, etc.)
type InternalDBErr struct {
	Op    string
	Cause error
}

func (e *InternalDBErr) Error() string {
	return fmt.Sprintf("database operation '%s' failed: %v", e.Op, e.Cause)
}

func (*InternalDBErr) Persistence() {}

func NewInternalDBErr(op string, err error) *InternalDBErr {
	return &InternalDBErr{Op: op, Cause: err}
}
