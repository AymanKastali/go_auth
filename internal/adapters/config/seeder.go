package config

import (
	"go_auth/internal/adapters/shared/errors/cfgerr"
	"os"
)

type SeederConfig struct {
	adminEmail    string
	adminPassword string
}

func (c *SeederConfig) AdminEmail() string    { return c.adminEmail }
func (c *SeederConfig) AdminPassword() string { return c.adminPassword }

func LoadSeederConfig() (*SeederConfig, error) {
	const module = "Seeder"

	email := os.Getenv("GA_ADMIN_EMAIL")
	if email == "" {
		return nil, cfgerr.NewInvalidConfigErr(module, "GA_ADMIN_EMAIL", cfgerr.ErrRequired)
	}

	password := os.Getenv("GA_ADMIN_PASSWORD")
	if password == "" {
		return nil, cfgerr.NewInvalidConfigErr(module, "GA_ADMIN_PASSWORD", cfgerr.ErrRequired)
	}

	return &SeederConfig{
		adminEmail:    email,
		adminPassword: password,
	}, nil
}
