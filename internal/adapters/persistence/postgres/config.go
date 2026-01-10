package postgres

import (
	"fmt"
	"go_auth/internal/adapters/shared"
	"os"
)

const module = "Postgres"

type PostgresConfig struct {
	host     string
	user     string
	password string
	dbName   string
	port     string
	sslMode  string
}

func LoadPostgresConfig() (*PostgresConfig, error) {
	// Helper to reduce repetitive code
	getRequired := func(key string) (string, error) {
		val := os.Getenv(key)
		if val == "" {
			return "", shared.NewMissingVarErr(module, key)
		}
		return val, nil
	}

	var err error
	cfg := &PostgresConfig{}

	if cfg.host, err = getRequired("GA_POSTGRES_HOST"); err != nil {
		return nil, err
	}
	if cfg.user, err = getRequired("GA_POSTGRES_USER"); err != nil {
		return nil, err
	}
	if cfg.password, err = getRequired("GA_POSTGRES_PASSWORD"); err != nil {
		return nil, err
	}
	if cfg.dbName, err = getRequired("GA_POSTGRES_DB"); err != nil {
		return nil, err
	}
	if cfg.port, err = getRequired("GA_POSTGRES_PORT"); err != nil {
		return nil, err
	}

	cfg.sslMode = os.Getenv("GA_POSTGRES_SSLMODE")
	if cfg.sslMode == "" {
		cfg.sslMode = "disable"
	}

	return cfg, nil
}

func (c *PostgresConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=%s",
		c.host, c.user, c.password, c.dbName, c.port, c.sslMode,
	)
}

func (c *PostgresConfig) Host() string   { return c.host }
func (c *PostgresConfig) Port() string   { return c.port }
func (c *PostgresConfig) DBName() string { return c.dbName }
