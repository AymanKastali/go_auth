package postgres

import "gorm.io/gorm"

func Migrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&UserModel{},
		&SessionModel{},
	)
}
