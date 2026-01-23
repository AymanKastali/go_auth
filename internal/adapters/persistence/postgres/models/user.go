package models

import (
	"time"
)

type User struct {
	ID             string `gorm:"primaryKey;type:uuid"`
	Email          string `gorm:"uniqueIndex;not null"`
	HashedPassword string `gorm:"not null"`
	Status         string `gorm:"type:varchar(20);not null"`
	Roles          []Role `gorm:"many2many:user_roles;"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
	DeletedAt      *time.Time `gorm:"index"`
}

func (User) TableName() string {
	return "users"
}
