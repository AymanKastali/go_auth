package seeder

import (
	"fmt"
	"os"
)

type SeederConfig struct {
	adminEmail    string
	adminPassword string
}

func (c *SeederConfig) AdminEmail() string    { return c.adminEmail }
func (c *SeederConfig) AdminPassword() string { return c.adminPassword }

func NewSeederConfig() (*SeederConfig, error) {
	email := os.Getenv("GA_ADMIN_EMAIL")
	if email == "" {
		return nil, fmt.Errorf("missing GA_ADMIN_EMAIL")
	}

	password := os.Getenv("GA_ADMIN_PASSWORD")
	if password == "" {
		return nil, fmt.Errorf("missing GA_ADMIN_PASSWORD")
	}

	return &SeederConfig{
		adminEmail:    email,
		adminPassword: password,
	}, nil
}
