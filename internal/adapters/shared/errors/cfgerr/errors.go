package cfgerr

import (
	"errors"
	"fmt"
)

var (
	// General
	ErrRequired      = errors.New("value is required but was empty")
	ErrInvalidFormat = errors.New("value has an invalid format")
	// JWT
	ErrNotRSAPrivateKey = errors.New("provided data is not a valid RSA private key")
	ErrNotRSAPublicKey  = errors.New("provided data is not a valid RSA public key")
	ErrInsecureKeySize  = errors.New("RSA key size is too small (minimum 2048 bits required)")
	ErrInvalidPEM       = errors.New("failed to decode PEM block")
)

type ConfigErr interface {
	error
	Adapters()
}

type InvalidConfigErr struct {
	Module string
	Key    string
	Reason error
}

func (e *InvalidConfigErr) Error() string {
	return fmt.Sprintf("[%s Config Error] key '%s' is invalid: %v", e.Module, e.Key, e.Reason)
}

func (*InvalidConfigErr) Adapters() {}

func (e *InvalidConfigErr) Unwrap() error {
	return e.Reason
}

func NewInvalidConfigErr(module, key string, err error) *InvalidConfigErr {
	return &InvalidConfigErr{
		Module: module,
		Key:    key,
		Reason: err,
	}
}
