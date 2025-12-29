package models

import (
	"time"

	"gorm.io/datatypes"
)

type User struct {
	ID           string                      `gorm:"primaryKey;type:uuid"`
	Email        string                      `gorm:"uniqueIndex;not null"`
	PasswordHash string                      `gorm:"not null"`
	Status       string                      `gorm:"type:varchar(20);not null"`
	Roles        datatypes.JSONSlice[string] `gorm:"type:jsonb"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    *time.Time `gorm:"index"`
}

func (User) TableName() string {
	return "users"
}
