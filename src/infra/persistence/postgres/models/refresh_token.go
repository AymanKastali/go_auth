package models

import (
	"time"

	"gorm.io/gorm"
)

type RefreshToken struct {
	gorm.Model
	ID        string    `gorm:"primaryKey;type:uuid"`
	UserId    string    `gorm:"not null;index"`
	User      User      `gorm:"foreignKey:UserId"` // optional struct relation
	DeviceId  string    `gorm:"type:uuid;not null;index"`
	Device    Device    `gorm:"foreignKey:DeviceId"` // optional struct relation
	Token     string    `gorm:"not null"`            // TODO store hashed token
	ExpiresAt time.Time `gorm:"not null"`
	RevokedAt *time.Time
}

func (RefreshToken) TableName() string {
	return "refresh_tokens"
}
