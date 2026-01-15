package postgres

import (
	"errors"
	"fmt"
	"os"
)

type PostgresConfig struct {
	host     string
	user     string
	password string
	dbName   string
	port     string
	sslMode  string
}

func NewPostgresConfig() (*PostgresConfig, error) {
	cfg := &PostgresConfig{}

	cfg.host = os.Getenv("GA_POSTGRES_HOST")
	if cfg.host == "" {
		return nil, errors.New("GA_POSTGRES_HOST is required")
	}

	cfg.user = os.Getenv("GA_POSTGRES_USER")
	if cfg.user == "" {
		return nil, errors.New("GA_POSTGRES_USER is required")
	}

	cfg.password = os.Getenv("GA_POSTGRES_PASSWORD")
	if cfg.password == "" {
		return nil, errors.New("GA_POSTGRES_PASSWORD is required")
	}

	cfg.dbName = os.Getenv("GA_POSTGRES_DB")
	if cfg.dbName == "" {
		return nil, errors.New("GA_POSTGRES_DB is required")
	}

	cfg.port = os.Getenv("GA_POSTGRES_PORT")
	if cfg.port == "" {
		return nil, errors.New("GA_POSTGRES_PORT is required")
	}

	cfg.sslMode = os.Getenv("GA_POSTGRES_SSLMODE")
	if cfg.sslMode == "" {
		cfg.sslMode = "disable"
	}

	return cfg, nil
}

// DSN returns the connection string for the database driver
func (c *PostgresConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=%s",
		c.host, c.user, c.password, c.dbName, c.port, c.sslMode,
	)
}

// Getters for individual fields
func (c *PostgresConfig) Host() string   { return c.host }
func (c *PostgresConfig) Port() string   { return c.port }
func (c *PostgresConfig) DBName() string { return c.dbName }
