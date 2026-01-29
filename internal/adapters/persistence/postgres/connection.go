package postgres

import (
	"context"
	"time"

	// Import your domain for the internal error type

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func NewPostgresConnection(url string) (*gorm.DB, error) {
	// 1. Open Connection
	db, err := gorm.Open(postgres.Open(url), &gorm.Config{
		TranslateError: true, // Crucial for mapping GORM errors to DB-specific errors
	})

	if err != nil {
		return nil, err
	}

	// 2. Access Underlying SQL Driver
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}

	// 3. Health Check (Ping)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := sqlDB.PingContext(ctx); err != nil {
		return nil, err
	}

	// 4. Connection Pool Settings
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

	if err := sqlDB.Close(); err != nil {
		return err
	}

	return nil
}
