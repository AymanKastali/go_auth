package jwt

import (
	"errors"
)

var (
	ErrInvalidFormat    = errors.New("value has an invalid format")
	ErrInvalidPEM       = errors.New("failed to decode PEM block")
	ErrNotRSAPrivateKey = errors.New("provided data is not a valid RSA private key")
	ErrNotRSAPublicKey  = errors.New("provided data is not a valid RSA public key")
	ErrInsecureKeySize  = errors.New("RSA key size is too small (minimum 2048 bits required)")
)
