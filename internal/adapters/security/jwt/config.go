package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"
)

type JWTConfig struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Issuer     string
	Audience   string
	AccessTTL  time.Duration
	RefreshTTL time.Duration
}

func LoadJWTConfigFromEnv() (*JWTConfig, error) {
	return loadJWTConfig(os.Getenv)
}

func loadJWTConfig(getenv func(string) string) (*JWTConfig, error) {
	issuer := getenv("JWT_ISSUER")
	if issuer == "" {
		return nil, errors.New("JWT_ISSUER not set")
	}

	audience := getenv("JWT_AUDIENCE")
	if audience == "" {
		return nil, errors.New("JWT_AUDIENCE not set")
	}

	accessTTL, err := time.ParseDuration(getenv("JWT_ACCESS_TTL"))
	if err != nil {
		return nil, fmt.Errorf("JWT_ACCESS_TTL: %w", err)
	}

	refreshTTL, err := time.ParseDuration(getenv("JWT_REFRESH_TTL"))
	if err != nil {
		return nil, fmt.Errorf("JWT_REFRESH_TTL: %w", err)
	}

	priv, err := loadRSAPrivateKey(getenv("JWT_PRIVATE_KEY"))
	if err != nil {
		return nil, fmt.Errorf("JWT_PRIVATE_KEY: %w", err)
	}

	pub, err := loadRSAPublicKey(getenv("JWT_PUBLIC_KEY"))
	if err != nil {
		return nil, fmt.Errorf("JWT_PUBLIC_KEY: %w", err)
	}

	return &JWTConfig{
		PrivateKey: priv,
		PublicKey:  pub,
		Issuer:     issuer,
		Audience:   audience,
		AccessTTL:  accessTTL,
		RefreshTTL: refreshTTL,
	}, nil
}

func loadRSAPrivateKey(pemValue string) (*rsa.PrivateKey, error) {
	if pemValue == "" {
		return nil, errors.New("not set")
	}

	block, _ := pem.Decode([]byte(pemValue))
	if block == nil {
		return nil, errors.New("invalid PEM data")
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		validateRSAKeySize(key.N.BitLen())
		return key, nil
	}

	pk, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	key, ok := pk.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}

	validateRSAKeySize(key.N.BitLen())
	return key, nil
}

func loadRSAPublicKey(pemValue string) (*rsa.PublicKey, error) {
	if pemValue == "" {
		return nil, errors.New("not set")
	}

	block, _ := pem.Decode([]byte(pemValue))
	if block == nil {
		return nil, errors.New("invalid PEM data")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	validateRSAKeySize(rsaPub.N.BitLen())
	return rsaPub, nil
}

func validateRSAKeySize(bits int) error {
	if bits < 2048 {
		return errors.New("RSA key size < 2048 bits")
	}
	return nil
}
