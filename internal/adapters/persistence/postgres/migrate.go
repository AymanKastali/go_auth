package postgres

import (
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/adapters/persistence/postgres/pgerr"

	"gorm.io/gorm"
)

func AutoMigrate(db *gorm.DB) error {
	err := db.SetupJoinTable(&models.User{}, "Roles", &models.UserRole{})
	if err != nil {
		return pgerr.WrapInternal(err, "failed to setup join table for User-Roles")
	}

	err = db.AutoMigrate(
		&models.User{},
		&models.RenewalToken{},
		&models.Device{},
		&models.Role{},
		&models.UserRole{},
	)

	if err != nil {
		return pgerr.WrapUnavailable(err, "database auto-migration failed")
	}

	return nil
}
