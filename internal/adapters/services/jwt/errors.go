package jwt

import (
	"errors"
	"fmt"
)

// --- The Contract (Interface) ---
// This ensures that any error produced by this package satisfies
// both the standard error and your Infrastructure marker.
type JWTError interface {
	error
	Adapters()
}

// --- Private Sentinels ---
var (
	errInvalidFormat    = errors.New("value has an invalid format")
	errInvalidPEM       = errors.New("failed to decode PEM block")
	errNotRSAPrivateKey = errors.New("provided data is not a valid RSA private key")
	errNotRSAPublicKey  = errors.New("provided data is not a valid RSA public key")
	errInsecureKeySize  = errors.New("RSA key size is too small (minimum 2048 bits required)")
	errUnexpectedMethod = errors.New("unexpected signing method")
	errInvalidToken     = errors.New("invalid token")
	errTypeMismatch     = errors.New("token type mismatch")
	errMissingType      = errors.New("required 'type' field is missing in claims")
	errSignFailure      = errors.New("failed to sign token with private key")
)

// --- Private Implementation ---
type jwtError struct {
	op     string
	reason error
}

func (e *jwtError) Error() string {
	return fmt.Sprintf("[JWT Error] operation '%s' failed: %v", e.op, e.reason)
}

func (e *jwtError) Adapters()     {}
func (e *jwtError) Unwrap() error { return e.reason }

// --- New Methods (Returning the JWTError Interface) ---

func NewSignErr(err error) JWTError {
	return &jwtError{op: "Signing", reason: errors.Join(errSignFailure, err)}
}

func NewInvalidPEMErr() JWTError {
	return &jwtError{op: "PEM Decode", reason: errInvalidPEM}
}

func NewInvalidFormatErr() JWTError {
	return &jwtError{op: "Format Check", reason: errInvalidFormat}
}

func NewKeyTypeErr(isPrivate bool) JWTError {
	reason := errNotRSAPublicKey
	if isPrivate {
		reason = errNotRSAPrivateKey
	}
	return &jwtError{op: "Key Type Validation", reason: reason}
}

func NewInsecureKeyErr() JWTError {
	return &jwtError{op: "Security Policy", reason: errInsecureKeySize}
}

func NewUnexpectedMethodErr() JWTError {
	return &jwtError{op: "Signature Validation", reason: errUnexpectedMethod}
}

func NewInvalidTokenErr(reason error) JWTError {
	if reason == nil {
		reason = errInvalidToken
	}
	return &jwtError{op: "Token Validation", reason: reason}
}

func NewTypeMismatchErr() JWTError {
	return &jwtError{op: "Claims Validation", reason: errTypeMismatch}
}

func NewMissingTypeErr() JWTError {
	return &jwtError{op: "Claims Validation", reason: errMissingType}
}
