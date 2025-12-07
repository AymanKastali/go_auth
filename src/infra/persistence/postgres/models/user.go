package models

import (
	"gorm.io/gorm"
)

type UserModel struct {
	gorm.Model
	ID           string `gorm:"primaryKey;type:uuid"`
	Email        string `gorm:"uniqueIndex;not null"`
	PasswordHash string `gorm:"not null"`
	IsActive     bool   `gorm:"not null"`
}

func (UserModel) TableName() string {
	return "users"
}
