package config

import (
	"errors"
	"os"
)

type SeederConfig struct {
	AdminEmail    string
	AdminPassword string
}

func LoadSeederConfig() (*SeederConfig, error) {
	email := os.Getenv("ADMIN_EMAIL")
	password := os.Getenv("ADMIN_PASSWORD")

	if email == "" || password == "" {
		return nil, errors.New("seeder config: missing required env vars")
	}

	return &SeederConfig{
		AdminEmail:    email,
		AdminPassword: password,
	}, nil
}
