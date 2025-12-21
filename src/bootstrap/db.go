package bootstrap

import (
	"go_auth/src/infra/persistence/postgres"

	"gorm.io/gorm"
)

func newDatabase() (*gorm.DB, error) {
	db, err := postgres.NewPostgresConnection()
	if err != nil {
		return nil, err
	}

	postgres.AutoMigrate(db)
	return db, nil
}
