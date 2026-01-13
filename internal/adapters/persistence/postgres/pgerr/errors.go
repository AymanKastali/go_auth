package pgerr

import (
	"errors"
)

var (
	ErrConnFailure = errors.New("connection establishment failed")
	ErrUnavailable = errors.New("repository unavailable")
	ErrTimeout     = errors.New("repository timeout")
)
