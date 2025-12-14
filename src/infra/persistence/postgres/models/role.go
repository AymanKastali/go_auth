package models

import "gorm.io/gorm"

type Role struct {
	gorm.Model
	ID          string       `gorm:"primaryKey;type:uuid"`
	Name        string       `gorm:"uniqueIndex;not null" json:"name"`
	Description string       `json:"description"`
	Permissions []Permission `gorm:"many2many:role_permissions;" json:"permissions"`
}

func (Role) TableName() string {
	return "roles"
}
