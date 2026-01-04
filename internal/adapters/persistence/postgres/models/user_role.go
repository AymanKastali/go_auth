package models

import (
	"time"
)

type UserRole struct {
	UserID    string    `gorm:"primaryKey;type:uuid"`
	RoleID    string    `gorm:"primaryKey;type:uuid"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
}

func (UserRole) TableName() string {
	return "user_roles"
}
