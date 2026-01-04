package postgres

import (
	"go_auth/internal/adapters/persistence/postgres/models"

	"gorm.io/gorm"
)

func AutoMigrate(db *gorm.DB) error {
	err := db.SetupJoinTable(&models.User{}, "Roles", &models.UserRole{})
	if err != nil {
		return err
	}

	return db.AutoMigrate(
		&models.User{},
		&models.RefreshToken{},
		&models.Device{},
		&models.Role{},
		&models.UserRole{},
	)
}
