package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"time"
)

type JWTConfig struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	issuer     string
	audience   string
	accessTTL  time.Duration
	refreshTTL time.Duration
}

func (c *JWTConfig) PrivateKey() *rsa.PrivateKey { return c.privateKey }
func (c *JWTConfig) PublicKey() *rsa.PublicKey   { return c.publicKey }
func (c *JWTConfig) Issuer() string              { return c.issuer }
func (c *JWTConfig) Audience() string            { return c.audience }
func (c *JWTConfig) AccessTTL() time.Duration    { return c.accessTTL }
func (c *JWTConfig) RefreshTTL() time.Duration   { return c.refreshTTL }

func NewJWTConfig() (*JWTConfig, error) {
	cfg := &JWTConfig{}

	// 1. Strings
	cfg.issuer = os.Getenv("GA_JWT_ISSUER")
	if cfg.issuer == "" {
		return nil, errors.New("GA_JWT_ISSUER is required")
	}
	cfg.audience = os.Getenv("GA_JWT_AUDIENCE")
	if cfg.audience == "" {
		return nil, errors.New("GA_JWT_AUDIENCE is required")
	}

	// 2. Durations
	accessStr := os.Getenv("GA_JWT_ACCESS_TTL")
	d, err := time.ParseDuration(accessStr)
	if err != nil {
		return nil, errors.New("invalid GA_JWT_ACCESS_TTL format")
	}
	cfg.accessTTL = d

	refreshStr := os.Getenv("GA_JWT_REFRESH_TTL")
	d, err = time.ParseDuration(refreshStr)
	if err != nil {
		return nil, errors.New("invalid GA_JWT_REFRESH_TTL format")
	}
	cfg.refreshTTL = d

	// 3. Keys
	privPEM := os.Getenv("GA_JWT_PRIVATE_KEY")
	if privPEM == "" {
		return nil, errors.New("GA_JWT_PRIVATE_KEY is required")
	}
	cfg.privateKey, err = parseRSAPrivateKey(privPEM)
	if err != nil {
		return nil, err
	}

	pubPEM := os.Getenv("GA_JWT_PUBLIC_KEY")
	if pubPEM == "" {
		return nil, errors.New("GA_JWT_PUBLIC_KEY is required")
	}
	cfg.publicKey, err = parseRSAPublicKey(pubPEM)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

// --- Internal Helper Logic ---

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
