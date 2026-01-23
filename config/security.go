package config

import (
	"errors"
	"os"
	"strconv"
)

type SecurityConfig struct {
	HMACSecret                     []byte
	BcryptCost                     int
	SessionRenewalTokenSecretBytes int
}

func loadSecurityConfig() (*SecurityConfig, error) {
	secret := os.Getenv("GA_HMAC_SECRET")
	if secret == "" {
		return nil, errors.New("GA_HMAC_SECRET is required")
	}

	costStr := os.Getenv("GA_BCRYPT_COST")
	cost := 12
	if costStr != "" {
		parsed, err := strconv.Atoi(costStr)
		if err != nil || parsed < 4 || parsed > 31 {
			return nil, errors.New("GA_BCRYPT_COST must be an integer between 4 and 31")
		}
		cost = parsed
	}

	bytes := 32 // default = 256-bit entropy
	if sizeStr := os.Getenv("GA_SESSION_RENEWAL_TOKEN_SECRET_BYTES"); sizeStr != "" {
		parsed, err := strconv.Atoi(sizeStr)
		if err != nil || parsed < 16 || parsed > 128 {
			return nil, errors.New("GA_SESSION_RENEWAL_TOKEN_SECRET_BYTES must be between 16 and 128")
		}
		bytes = parsed
	}

	return &SecurityConfig{
		HMACSecret:                     []byte(secret),
		BcryptCost:                     cost,
		SessionRenewalTokenSecretBytes: bytes,
	}, nil
}
