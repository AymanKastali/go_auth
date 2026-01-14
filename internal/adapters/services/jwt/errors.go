package jwt

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidFormat    = errors.New("value has an invalid format")
	ErrInvalidPEM       = errors.New("failed to decode PEM block")
	ErrNotRSAPrivateKey = errors.New("provided data is not a valid RSA private key")
	ErrNotRSAPublicKey  = errors.New("provided data is not a valid RSA public key")
	ErrInsecureKeySize  = errors.New("RSA key size is too small (minimum 2048 bits required)")
)

type tokenError struct {
	inner     error
	msg       string
	isExpired bool
	isInvalid bool
}

func (e *tokenError) Error() string {
	return fmt.Sprintf("%s: %v", e.msg, e.inner)
}

func (e *tokenError) Unwrap() error { return e.inner }

// --- Checkers ---
func IsExpired(err error) bool {
	var te *tokenError
	return errors.As(err, &te) && te.isExpired
}

func IsInvalid(err error) bool {
	var te *tokenError
	return errors.As(err, &te) && te.isInvalid
}

// --- Factories ---
func WrapExpired(err error, msg string) error {
	return &tokenError{inner: err, msg: msg, isExpired: true}
}

func WrapInvalid(err error, msg string) error {
	return &tokenError{inner: err, msg: msg, isInvalid: true}
}
