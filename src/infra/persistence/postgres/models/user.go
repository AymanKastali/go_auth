package models

import (
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	ID           string       `gorm:"primaryKey;type:uuid"`
	Email        string       `gorm:"uniqueIndex;not null"`
	PasswordHash string       `gorm:"not null"`
	Status       string       `gorm:"type:varchar(20);not null"`
	Memberships  []Membership `gorm:"foreignKey:UserID"`
}

func (User) TableName() string {
	return "users"
}
