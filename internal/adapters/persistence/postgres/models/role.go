package models

import (
	"time"
)

type Role struct {
	ID        string `gorm:"primaryKey;type:uuid"`
	Name      string `gorm:"uniqueIndex;not null"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time `gorm:"index"`
}

func (Role) TableName() string {
	return "roles"
}
