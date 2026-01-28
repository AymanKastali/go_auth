package bootstrap

import "go_auth/internal/adapters"

func LoadConfig() *adapters.Config {
	cfg, err := adapters.Load()
	if err != nil {
		panic(err)
	}
	return cfg
}
