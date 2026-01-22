package config

import (
	"fmt"
	"os"
)

type AdminSeederConfig struct {
	AdminEmail    string
	AdminPassword string
}

func loadAdminSeederConfig() (*AdminSeederConfig, error) {
	adminEmail := os.Getenv("GA_ADMIN_EMAIL")
	if adminEmail == "" {
		return nil, fmt.Errorf("missing GA_ADMIN_EMAIL")
	}

	adminPassword := os.Getenv("GA_ADMIN_PASSWORD")
	if adminPassword == "" {
		return nil, fmt.Errorf("missing GA_ADMIN_PASSWORD")
	}

	return &AdminSeederConfig{AdminEmail: adminEmail, AdminPassword: adminPassword}, nil
}
