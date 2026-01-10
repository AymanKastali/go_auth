package fibererr

import (
	"errors"
	"fmt"
)

type FiberErr interface {
	error
	Adapters()
}

// --- Private Sentinels (The "What") ---
var (
	errInvalidPortRange = errors.New("port must be between 1 and 65535")
	errInvalidFormat    = errors.New("value is not a valid integer")
	errUnknown          = errors.New("unknown configuration error")
)

// --- Private Implementation (The "Where") ---
type fiberErr struct {
	op     string
	key    string
	reason error
}

func (e *fiberErr) Error() string {
	return fmt.Sprintf("[Fiber Config Error] key '%s' failed during %s: %v", e.key, e.op, e.reason)
}

func (e *fiberErr) Adapters()     {}
func (e *fiberErr) Unwrap() error { return e.reason }

// --- New Methods (The "How") ---

// NewInvalidPortErr handles specific logic violations for network ports.
func NewInvalidPortErr(key string) FiberErr {
	return &fiberErr{
		op:     "Range Validation",
		key:    key,
		reason: errInvalidPortRange,
	}
}

// NewParseErr handles string-to-int conversion failures.
func NewParseErr(key string, err error) FiberErr {
	if err == nil {
		err = errUnknown
	}
	return &fiberErr{
		op:     "Type Conversion",
		key:    key,
		reason: errors.Join(errInvalidFormat, err),
	}
}
