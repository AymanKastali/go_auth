package config

import "os"

type SeederConfig struct {
	AdminEmail    string
	AdminPassword string
}

func LoadSeederConfig() (*SeederConfig, error) {
	return &SeederConfig{
		AdminEmail:    os.Getenv("ADMIN_EMAIL"),
		AdminPassword: os.Getenv("ADMIN_PASSWORD"),
	}, nil
}
