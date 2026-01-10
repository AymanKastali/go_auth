package shared

import (
	"fmt"
)

type ConfigErr struct {
	module string
	key    string
	reason error
}

func (e *ConfigErr) Error() string {
	if e.key != "" {
		return fmt.Sprintf("[%s Config Error] key '%s' is invalid: %v", e.module, e.key, e.reason)
	}
	return fmt.Sprintf("[%s Error]: %v", e.module, e.reason)
}

func (e *ConfigErr) Adapters()     {}
func (e *ConfigErr) Unwrap() error { return e.reason }

func NewConfigError(module, key string, reason error) error {
	return &ConfigErr{
		module: module,
		key:    key,
		reason: reason,
	}
}

// Missing Variable Error
type MissingVarErr struct {
	module string
	key    string
}

func (e *MissingVarErr) Error() string {
	if e.key != "" {
		return fmt.Sprintf("[%s Missing Variable Error] key '%s' is required but was empty", e.module, e.key)
	}
	return fmt.Sprintf("[%s Error] required configuration is missing", e.module)
}

func (e *MissingVarErr) Adapters() {}

func NewMissingVarErr(module, key string) error {
	return &MissingVarErr{
		module: module,
		key:    key,
	}
}

// InvalidVarErr handles cases where the variable exists but parsing fails (e.g., bad RSA or Duration)
type InvalidVarErr struct {
	module string
	key    string
	reason error
}

func (e *InvalidVarErr) Error() string {
	return fmt.Sprintf("[%s Invalid Variable Error] key '%s' is malformed: %v", e.module, e.key, e.reason)
}

func (e *InvalidVarErr) Adapters()     {}
func (e *InvalidVarErr) Unwrap() error { return e.reason }

func NewInvalidVarErr(module, key string, reason error) error {
	return &InvalidVarErr{
		module: module,
		key:    key,
		reason: reason,
	}
}
