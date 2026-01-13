package seed

import (
	"go_auth/internal/adapters/shared"
	"os"
)

const module = "Seeder"

type SeederConfig struct {
	adminEmail    string
	adminPassword string
}

func (c *SeederConfig) AdminEmail() string    { return c.adminEmail }
func (c *SeederConfig) AdminPassword() string { return c.adminPassword }

func LoadSeederConfig() (*SeederConfig, error) {
	getRequired := func(key string) (string, error) {
		val := os.Getenv(key)
		if val == "" {
			return "", shared.NewMissingVarErr(module, key)
		}
		return val, nil
	}

	var err error
	cfg := &SeederConfig{}

	if cfg.adminEmail, err = getRequired("GA_ADMIN_EMAIL"); err != nil {
		return nil, err
	}

	if cfg.adminPassword, err = getRequired("GA_ADMIN_PASSWORD"); err != nil {
		return nil, err
	}
	return cfg, nil
}
