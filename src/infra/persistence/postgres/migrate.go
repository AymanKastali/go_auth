package postgres

import (
	"go_auth/src/infra/persistence/postgres/models"

	"gorm.io/gorm"
)

func AutoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&models.User{},
		&models.Organization{},
		&models.Membership{},
	)
}
