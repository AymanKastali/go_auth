package postgres

import (
	"go_auth/internal/adapters/persistence/postgres/models"

	"gorm.io/gorm"
)

func AutoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&models.User{},
		&models.RefreshToken{},
		&models.Device{},
	)
}
