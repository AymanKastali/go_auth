package main

import "go_auth/internal/adapters"

func loadConfig() *adapters.Config {
	cfg, err := adapters.Load()
	if err != nil {
		panic(err)
	}
	return cfg
}
