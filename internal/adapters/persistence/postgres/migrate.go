package postgres

import (
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/adapters/persistence/postgres/pgerr"

	"gorm.io/gorm"
)

func AutoMigrate(db *gorm.DB) error {
	// 1. Setup Many-to-Many Join Table
	err := db.SetupJoinTable(&models.User{}, "Roles", &models.UserRole{})
	if err != nil {
		return pgerr.WrapInternal(err, "failed to setup join table for User-Roles")
	}

	// 2. Perform Migration
	err = db.AutoMigrate(
		&models.User{},
		&models.RefreshToken{},
		&models.Device{},
		&models.Role{},
		&models.UserRole{},
	)

	if err != nil {
		// FIX: Change WrapConnFailure to WrapUnavailable to match pgerr package
		return pgerr.WrapUnavailable(err, "database auto-migration failed")
	}

	return nil
}
