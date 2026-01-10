package seed

import (
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
		return nil, NewConfigError("GA_ADMIN_EMAIL", ErrRequired)
	}

	password := os.Getenv("GA_ADMIN_PASSWORD")
	if password == "" {
		return nil, NewConfigError("GA_ADMIN_PASSWORD", ErrRequired)
	}

	return &SeederConfig{
		adminEmail:    email,
		adminPassword: password,
	}, nil
}
