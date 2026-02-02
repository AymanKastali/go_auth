package main

import "go_auth/internal/adapters"

func loadConfig() (*adapters.Config, error) {
	return adapters.Load()
}
