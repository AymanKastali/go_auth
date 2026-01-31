package main

import (
	"go_auth/internal/adapters/persistence/postgres"
)

func setupDatabase(url string) *postgres.PersistenceFactory {
	pf, err := postgres.NewPersistenceFactory(url)
	if err != nil {
		panic(err)
	}

	return pf
}
