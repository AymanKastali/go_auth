package postgres

import (
	"fmt"
	"os"
)

type PostgresConfig struct {
	Host     string
	User     string
	Password string
	DBName   string
	Port     string
	SSLMode  string
}

func LoadPostgresConfig() (*PostgresConfig, error) {
	cfg := &PostgresConfig{
		Host:     os.Getenv("POSTGRES_HOST"),
		User:     os.Getenv("POSTGRES_USER"),
		Password: os.Getenv("POSTGRES_PASSWORD"),
		DBName:   os.Getenv("POSTGRES_DB"),
		Port:     os.Getenv("POSTGRES_PORT"),
		SSLMode:  os.Getenv("POSTGRES_SSLMODE"),
	}

	if cfg.Host == "" || cfg.User == "" || cfg.Password == "" || cfg.DBName == "" || cfg.Port == "" {
		return nil, fmt.Errorf("missing required Postgres environment variables")
	}

	if cfg.SSLMode == "" {
		cfg.SSLMode = "disable"
	}

	return cfg, nil
}

func (c *PostgresConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=%s",
		c.Host, c.User, c.Password, c.DBName, c.Port, c.SSLMode,
	)
}
