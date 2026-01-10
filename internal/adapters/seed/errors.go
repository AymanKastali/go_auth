package seed

import (
	"errors"
	"fmt"
)

var (
	ErrRequired      = errors.New("value is required but was empty")
	ErrInvalidFormat = errors.New("value has an invalid format")
)

// SeedErr is the concrete struct.
// In Go, usually custom error structs are named with a capital to be exported,
// but the fields can stay internal to the package.
type SeedErr struct {
	module string
	key    string
	reason error
}

func (e *SeedErr) Error() string {
	if e.key != "" {
		return fmt.Sprintf("[%s Config Error] key '%s' is invalid: %v", e.module, e.key, e.reason)
	}
	return fmt.Sprintf("[%s Error]: %v", e.module, e.reason)
}

func (e *SeedErr) Adapters()     {}
func (e *SeedErr) Unwrap() error { return e.reason }

func NewConfigError(key string, reason error) error {
	return &SeedErr{
		module: "Seed",
		key:    key,
		reason: reason,
	}
}
