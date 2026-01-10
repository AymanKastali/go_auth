package jwt

import (
	"errors"
	"fmt"
)

var (
	ErrRequired         = errors.New("value is required but was empty")
	ErrInvalidFormat    = errors.New("value has an invalid format")
	ErrInvalidPEM       = errors.New("failed to decode PEM block")
	ErrNotRSAPrivateKey = errors.New("provided data is not a valid RSA private key")
	ErrNotRSAPublicKey  = errors.New("provided data is not a valid RSA public key")
	ErrInsecureKeySize  = errors.New("RSA key size is too small (minimum 2048 bits required)")

	ErrUnexpectedMethod = errors.New("unexpected signing method")
	ErrInvalidToken     = errors.New("invalid token")
	ErrTypeMismatch     = errors.New("token type mismatch")
)

type jwtError struct {
	module string
	key    string
	reason error
}

func (e *jwtError) Error() string {
	if e.key != "" {
		return fmt.Sprintf("[%s Config Error] key '%s' is invalid: %v", e.module, e.key, e.reason)
	}
	return fmt.Sprintf("[%s Error]: %v", e.module, e.reason)
}

func (e *jwtError) Adapters()     {} // Interface Marker
func (e *jwtError) Unwrap() error { return e.reason }

// NewConfigError is used specifically during environment/config loading
func NewConfigError(key string, reason error) error {
	return &jwtError{
		module: "JWT",
		key:    key,
		reason: reason,
	}
}

// NewServiceError is used for runtime failures (signing, parsing)
func NewServiceError(reason error) error {
	return &jwtError{
		module: "JWT",
		reason: reason,
	}
}
