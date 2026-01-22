package postgres

import (
	"context"
	"go_auth/internal/adapters/persistence/postgres/pgerr"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func NewPostgresConnection(dsn string) (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		TranslateError: true,
	})

	if err != nil {
		return nil, pgerr.WrapUnavailable(err, "failed to open database connection")
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, pgerr.WrapUnavailable(err, "failed to access underlying sql driver")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := sqlDB.PingContext(ctx); err != nil {
		return nil, pgerr.WrapUnavailable(err, "database is unreachable")
	}

	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)

	return db, nil
}

func Close(db *gorm.DB) error {
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}
