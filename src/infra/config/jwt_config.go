package config

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
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
	issuer := os.Getenv("JWT_ISSUER")
	if issuer == "" {
		return nil, errors.New("JWT_ISSUER not set")
	}

	audience := os.Getenv("JWT_AUDIENCE")
	if audience == "" {
		return nil, errors.New("JWT_AUDIENCE not set")
	}

	accessTTL, err := time.ParseDuration(os.Getenv("JWT_ACCESS_TTL"))
	if err != nil {
		return nil, errors.New("invalid JWT_ACCESS_TTL")
	}

	refreshTTL, err := time.ParseDuration(os.Getenv("JWT_REFRESH_TTL"))
	if err != nil {
		return nil, errors.New("invalid JWT_REFRESH_TTL")
	}

	priv, err := loadRSAPrivateKeyFromEnv()
	if err != nil {
		return nil, err
	}

	pub, err := loadRSAPublicKeyFromEnv()
	if err != nil {
		return nil, err
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

// Load RSA private key, supports PKCS#1 and PKCS#8
func loadRSAPrivateKeyFromEnv() (*rsa.PrivateKey, error) {
	keyPEM := os.Getenv("JWT_PRIVATE_KEY")
	if keyPEM == "" {
		return nil, errors.New("JWT_PRIVATE_KEY not set")
	}

	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, errors.New("failed to parse JWT_PRIVATE_KEY PEM block")
	}

	// Try PKCS#1 first
	if priv, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return priv, nil
	}

	// Try PKCS#8
	privInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	priv, ok := privInterface.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}

	return priv, nil
}

// Load RSA public key (PKIX)
func loadRSAPublicKeyFromEnv() (*rsa.PublicKey, error) {
	keyPEM := os.Getenv("JWT_PUBLIC_KEY")
	if keyPEM == "" {
		return nil, errors.New("JWT_PUBLIC_KEY not set")
	}

	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, errors.New("failed to parse JWT_PUBLIC_KEY PEM block")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pub, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	return pub, nil
}
