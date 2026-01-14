package postgres

import (
	"go_auth/internal/adapters/persistence/postgres/pgerr"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func NewPostgresConnection(cfg *PostgresConfig) (*gorm.DB, error) {
	// 1. Open connection
	// TranslateError: true allows us to use errors.Is(err, gorm.ErrDuplicatedKey)
	db, err := gorm.Open(postgres.Open(cfg.DSN()), &gorm.Config{
		TranslateError: true,
	})

	if err != nil {
		// FIX: Change WrapConnFailure to WrapUnavailable to match your pgerr package
		return nil, pgerr.WrapUnavailable(err, "failed to open database connection")
	}

	// 2. Immediate Ping Check
	sqlDB, err := db.DB()
	if err != nil {
		return nil, pgerr.WrapUnavailable(err, "failed to access underlying sql driver")
	}

	if err := sqlDB.Ping(); err != nil {
		return nil, pgerr.WrapUnavailable(err, "database is unreachable")
	}

	return db, nil
}
