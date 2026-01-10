package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
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

func LoadJWTConfigFromEnv() (*JWTConfig, error) {
	return loadJWTConfig(os.Getenv)
}

func loadJWTConfig(getenv func(string) string) (*JWTConfig, error) {
	issuer := getenv("GA_JWT_ISSUER")
	if issuer == "" {
		return nil, NewConfigError("GA_JWT_ISSUER", ErrRequired)
	}

	audience := getenv("GA_JWT_AUDIENCE")
	if audience == "" {
		return nil, NewConfigError("GA_JWT_AUDIENCE", ErrRequired)
	}

	accessTTLStr := getenv("GA_JWT_ACCESS_TTL")
	accessTTL, err := time.ParseDuration(accessTTLStr)
	if err != nil {
		return nil, NewConfigError("GA_JWT_ACCESS_TTL", ErrInvalidFormat)
	}

	// Loading keys using the explicit constructor
	priv, err := loadRSAPrivateKey(getenv("GA_JWT_PRIVATE_KEY"))
	if err != nil {
		return nil, NewConfigError("GA_JWT_PRIVATE_KEY", err)
	}

	pub, err := loadRSAPublicKey(getenv("GA_JWT_PUBLIC_KEY"))
	if err != nil {
		return nil, NewConfigError("GA_JWT_PUBLIC_KEY", err)
	}

	return &JWTConfig{
		privateKey: priv,
		publicKey:  pub,
		issuer:     issuer,
		audience:   audience,
		accessTTL:  accessTTL,
	}, nil
}

func loadRSAPrivateKey(pemValue string) (*rsa.PrivateKey, error) {
	if pemValue == "" {
		return nil, ErrRequired
	}

	block, _ := pem.Decode([]byte(pemValue))
	if block == nil {
		return nil, ErrInvalidPEM
	}

	var key *rsa.PrivateKey
	// Try PKCS1
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		key = k
	} else {
		// Try PKCS8
		pk, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrInvalidFormat
		}
		k8, ok := pk.(*rsa.PrivateKey)
		if !ok {
			return nil, ErrNotRSAPrivateKey
		}
		key = k8
	}

	if err := validateRSAKeySize(key.N.BitLen()); err != nil {
		return nil, err
	}
	return key, nil
}

func loadRSAPublicKey(pemValue string) (*rsa.PublicKey, error) {
	if pemValue == "" {
		return nil, ErrRequired
	}

	block, _ := pem.Decode([]byte(pemValue))
	if block == nil {
		return nil, ErrInvalidPEM
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, ErrInvalidFormat
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, ErrNotRSAPublicKey
	}

	if err := validateRSAKeySize(rsaPub.N.BitLen()); err != nil {
		return nil, err
	}
	return rsaPub, nil
}

func validateRSAKeySize(bits int) error {
	if bits < 2048 {
		return ErrInsecureKeySize
	}
	return nil
}
