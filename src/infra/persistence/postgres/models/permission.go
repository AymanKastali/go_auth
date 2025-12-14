package models

import (
	"gorm.io/gorm"
)

type Permission struct {
	gorm.Model
	ID       string `gorm:"primaryKey;type:uuid"`
	Key      string `gorm:"uniqueIndex;not null" json:"key"` // e.g., "user:create"
	Name     string `json:"name"`                            // e.g., "Create User"
	Category string `json:"category"`                        // e.g., "User Management"
}

func (Permission) TableName() string {
	return "permissions"
}
