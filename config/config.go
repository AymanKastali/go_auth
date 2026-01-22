package config

import "fmt"

type Config struct {
	Fiber       FiberConfig
	Postgres    PostgresConfig
	JWT         JWTConfig
	AdminSeeder AdminSeederConfig
	Security    SecurityConfig
}

func LoadConfig() (*Config, error) {
	fiber, err := loadFiberConfig()
	if err != nil {
		return nil, fmt.Errorf("fiber config error: %w", err)
	}

	postgres, err := loadPostgresConfig()
	if err != nil {
		return nil, fmt.Errorf("postgres config error: %w", err)
	}

	jwt, err := loadJWTConfig()
	if err != nil {
		return nil, fmt.Errorf("jwt config error: %w", err)
	}

	adminSeeder, err := loadAdminSeederConfig()
	if err != nil {
		return nil, fmt.Errorf("admin seeder config error: %w", err)
	}

	security, err := loadSecurityConfig()
	if err != nil {
		return nil, fmt.Errorf("security config error: %w", err)
	}

	return &Config{
		Fiber:       *fiber,
		Postgres:    *postgres,
		JWT:         *jwt,
		AdminSeeder: *adminSeeder,
		Security:    *security,
	}, nil
}
