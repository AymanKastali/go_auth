package postgres

import (
	"go_auth/internal/adapters/persistence/postgres/pgerr"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func NewPostgresConnection(cfg *PostgresConfig) (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(cfg.DSN()), &gorm.Config{TranslateError: true})
	if err != nil {
		return nil, pgerr.ErrConnFailure
	}
	return db, nil
}
