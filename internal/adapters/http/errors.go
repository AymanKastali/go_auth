package http

import (
	"errors"
	"net/http"
)

// ProtocolError wraps an error with an HTTP-specific status code.
type ProtocolError struct {
	Status int
	Cause  error
}

func (e *ProtocolError) Error() string {
	return e.Cause.Error()
}

func (e *ProtocolError) Unwrap() error {
	return e.Cause
}

// NewBadRequest wraps an error as an HTTP 400.
func NewBadRequest(err error) error {
	return &ProtocolError{
		Status: http.StatusBadRequest,
		Cause:  err,
	}
}

// MapToStatus extracts the status code from an error if it's a ProtocolError.
func MapToStatus(err error) int {
	var pErr *ProtocolError
	if errors.As(err, &pErr) {
		return pErr.Status
	}
	return 0 // No specific protocol mapping
}
