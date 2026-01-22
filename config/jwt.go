package config

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

type JWTConfig struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Issuer     string
	Audience   string
}

func loadJWTConfig() (*JWTConfig, error) {
	privatePEM := os.Getenv("GA_JWT_PRIVATE_KEY")
	if privatePEM == "" {
		return nil, errors.New("GA_JWT_PRIVATE_KEY is required")
	}

	privateKey, err := parseRSAPrivateKey(privatePEM)
	if err != nil {
		return nil, err
	}

	publicPEM := os.Getenv("GA_JWT_PUBLIC_KEY")
	if publicPEM == "" {
		return nil, errors.New("GA_JWT_PUBLIC_KEY is required")
	}

	publicKey, err := parseRSAPublicKey(publicPEM)
	if err != nil {
		return nil, err
	}

	issuer := os.Getenv("GA_JWT_ISSUER")
	if issuer == "" {
		return nil, errors.New("GA_JWT_ISSUER is required")
	}

	audience := os.Getenv("GA_JWT_AUDIENCE")
	if audience == "" {
		return nil, errors.New("GA_JWT_AUDIENCE is required")
	}

	return &JWTConfig{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Issuer:     issuer,
		Audience:   audience,
	}, nil
}

func parseRSAPrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to decode private key PEM")
	}

	// Try PKCS1
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	// Try PKCS8
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid private key format: must be PKCS1 or PKCS8")
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}

	if rsaKey.N.BitLen() < 2048 {
		return nil, errors.New("insecure key size: minimum 2048 bits required")
	}

	return rsaKey, nil
}

func parseRSAPublicKey(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to decode public key PEM")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid public key format")
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	if rsaPub.N.BitLen() < 2048 {
		return nil, errors.New("insecure public key size")
	}

	return rsaPub, nil
}
