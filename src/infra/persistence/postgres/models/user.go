package models

import (
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	ID           string `gorm:"primaryKey;type:uuid"`
	Email        string `gorm:"uniqueIndex;not null"`
	PasswordHash string `gorm:"not null"`
	IsActive     bool   `gorm:"not null"`
	Roles        []Role `gorm:"many2many:user_roles;" json:"roles"`
}

func (User) TableName() string {
	return "users"
}
