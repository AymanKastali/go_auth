package pgerr

import (
	"errors"
)

var (
	ErrConnFailure = errors.New("connection establishment failed")
	ErrConflict    = errors.New("repository conflict")
	ErrNotFound    = errors.New("repository conflict")
	ErrUnavailable = errors.New("repository unavailable")
	ErrTimeout     = errors.New("repository timeout")
)
