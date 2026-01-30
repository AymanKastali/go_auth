package main

import (
	"go_auth/internal/adapters/persistence/postgres"

	"gorm.io/gorm"
)

func setupDatabase(url string) *gorm.DB {
	db, err := postgres.NewPostgresConnection(url)
	if err != nil {
		panic(err)
	}

	if err := postgres.Migrate(db); err != nil {
		panic(err)
	}

	return db
}
