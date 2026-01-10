package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"go_auth/internal/adapters/shared/errors/cfgerr"
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
	const module = "JWT"

	issuer := getenv("GA_JWT_ISSUER")
	if issuer == "" {
		return nil, cfgerr.NewInvalidConfigErr(module, "GA_JWT_ISSUER", cfgerr.ErrRequired)
	}

	audience := getenv("GA_JWT_AUDIENCE")
	if audience == "" {
		return nil, cfgerr.NewInvalidConfigErr(module, "GA_JWT_AUDIENCE", cfgerr.ErrRequired)
	}

	accessTTLStr := getenv("GA_JWT_ACCESS_TTL")
	accessTTL, err := time.ParseDuration(accessTTLStr)
	if err != nil {
		return nil, cfgerr.NewInvalidConfigErr(module, "GA_JWT_ACCESS_TTL", cfgerr.ErrInvalidFormat)
	}

	refreshTTLStr := getenv("GA_JWT_REFRESH_TTL")
	refreshTTL, err := time.ParseDuration(refreshTTLStr)
	if err != nil {
		return nil, cfgerr.NewInvalidConfigErr(module, "GA_JWT_REFRESH_TTL", cfgerr.ErrInvalidFormat)
	}

	priv, err := loadRSAPrivateKey(getenv("GA_JWT_PRIVATE_KEY"))
	if err != nil {
		return nil, cfgerr.NewInvalidConfigErr(module, "GA_JWT_PRIVATE_KEY", err)
	}

	pub, err := loadRSAPublicKey(getenv("GA_JWT_PUBLIC_KEY"))
	if err != nil {
		return nil, cfgerr.NewInvalidConfigErr(module, "GA_JWT_PUBLIC_KEY", err)
	}

	return &JWTConfig{
		privateKey: priv,
		publicKey:  pub,
		issuer:     issuer,
		audience:   audience,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
	}, nil
}

func loadRSAPrivateKey(pemValue string) (*rsa.PrivateKey, error) {
	if pemValue == "" {
		return nil, cfgerr.ErrRequired
	}

	block, _ := pem.Decode([]byte(pemValue))
	if block == nil {
		return nil, cfgerr.ErrInvalidPEM
	}

	var key *rsa.PrivateKey
	// Try PKCS1
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		key = k
	} else {
		// Try PKCS8
		pk, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, cfgerr.ErrInvalidFormat
		}
		k8, ok := pk.(*rsa.PrivateKey)
		if !ok {
			return nil, cfgerr.ErrNotRSAPrivateKey
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
		return nil, cfgerr.ErrRequired
	}

	block, _ := pem.Decode([]byte(pemValue))
	if block == nil {
		return nil, cfgerr.ErrInvalidPEM
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, cfgerr.ErrInvalidFormat
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, cfgerr.ErrNotRSAPublicKey
	}

	if err := validateRSAKeySize(rsaPub.N.BitLen()); err != nil {
		return nil, err
	}
	return rsaPub, nil
}

func validateRSAKeySize(bits int) error {
	if bits < 2048 {
		return cfgerr.ErrInsecureKeySize
	}
	return nil
}
