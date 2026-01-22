package config

import (
	"fmt"
	"os"
)

type PostgresConfig struct {
	DSN string
}

func loadPostgresConfig() (*PostgresConfig, error) {
	dsn := os.Getenv("GA_POSTGRES_DSN")
	if dsn == "" {
		return nil, fmt.Errorf("GA_POSTGRES_DSN environment variable required")
	}
	return &PostgresConfig{DSN: dsn}, nil
}
