package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"go_auth/internal/adapters/shared"
	"os"
	"time"
)

const module = "JWT"

type JWTConfig struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	issuer     string
	audience   string
	accessTTL  time.Duration
	refreshTTL time.Duration
}

// Getters
func (c *JWTConfig) PrivateKey() *rsa.PrivateKey { return c.privateKey }
func (c *JWTConfig) PublicKey() *rsa.PublicKey   { return c.publicKey }
func (c *JWTConfig) Issuer() string              { return c.issuer }
func (c *JWTConfig) Audience() string            { return c.audience }
func (c *JWTConfig) AccessTTL() time.Duration    { return c.accessTTL }
func (c *JWTConfig) RefreshTTL() time.Duration   { return c.refreshTTL }

func LoadJWTConfigFromEnv() (*JWTConfig, error) {
	return loadJWTConfig(os.Getenv)
}

func loadJWTConfig(getenv func(string) string) (*JWTConfig, error) {
	// Helper to utilize the shared package for all missing environment variables
	getRequired := func(key string) (string, error) {
		val := getenv(key)
		if val == "" {
			return "", shared.NewMissingVarErr(module, key)
		}
		return val, nil
	}

	var err error
	cfg := &JWTConfig{}

	// Required String Fields
	if cfg.issuer, err = getRequired("GA_JWT_ISSUER"); err != nil {
		return nil, err
	}
	if cfg.audience, err = getRequired("GA_JWT_AUDIENCE"); err != nil {
		return nil, err
	}

	// Required Duration Fields
	accessTTLStr, err := getRequired("GA_JWT_ACCESS_TTL")
	if err != nil {
		return nil, err
	}
	if cfg.accessTTL, err = time.ParseDuration(accessTTLStr); err != nil {
		return nil, shared.NewInvalidVarErr(module, "GA_JWT_ACCESS_TTL", err)
	}

	refreshTTLStr, err := getRequired("GA_JWT_REFRESH_TTL")
	if err != nil {
		return nil, err
	}
	if cfg.refreshTTL, err = time.ParseDuration(refreshTTLStr); err != nil {
		return nil, shared.NewInvalidVarErr(module, "GA_JWT_REFRESH_TTL", err)
	}

	// Cryptographic Key Fields
	privPEM, err := getRequired("GA_JWT_PRIVATE_KEY")
	if err != nil {
		return nil, err
	}
	if cfg.privateKey, err = loadRSAPrivateKey(privPEM); err != nil {
		return nil, shared.NewInvalidVarErr(module, "GA_JWT_PRIVATE_KEY", err)
	}

	pubPEM, err := getRequired("GA_JWT_PUBLIC_KEY")
	if err != nil {
		return nil, err
	}
	if cfg.publicKey, err = loadRSAPublicKey(pubPEM); err != nil {
		return nil, shared.NewInvalidVarErr(module, "GA_JWT_PUBLIC_KEY", err)
	}

	return cfg, nil
}

func loadRSAPrivateKey(pemValue string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemValue))
	if block == nil {
		return nil, NewInvalidPEMErr()
	}

	var key *rsa.PrivateKey
	// Attempt PKCS1 (Standard RSA)
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		key = k
	} else {
		// Attempt PKCS8 (Modern wrapped format)
		pk, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, NewInvalidFormatErr()
		}
		k8, ok := pk.(*rsa.PrivateKey)
		if !ok {
			return nil, NewKeyTypeErr(true)
		}
		key = k8
	}

	if err := validateRSAKeySize(key.N.BitLen()); err != nil {
		return nil, err
	}
	return key, nil
}

func loadRSAPublicKey(pemValue string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemValue))
	if block == nil {
		return nil, NewInvalidPEMErr()
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, NewInvalidFormatErr()
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, NewKeyTypeErr(false)
	}

	if err := validateRSAKeySize(rsaPub.N.BitLen()); err != nil {
		return nil, err
	}
	return rsaPub, nil
}

func validateRSAKeySize(bits int) error {
	// Secure minimum bit length check
	if bits < 2048 {
		return NewInsecureKeyErr()
	}
	return nil
}
