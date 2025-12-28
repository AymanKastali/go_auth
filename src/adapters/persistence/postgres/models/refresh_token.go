package models

import (
	"time"
)

type RefreshToken struct {
	ID        string    `gorm:"primaryKey;type:uuid"`
	UserID    string    `gorm:"not null;index"`
	User      User      `gorm:"foreignKey:UserID"` // optional struct relation
	DeviceID  string    `gorm:"type:uuid;not null;index"`
	Device    Device    `gorm:"foreignKey:DeviceID"` // optional struct relation
	Token     string    `gorm:"not null"`            // TODO store hashed token
	ExpiresAt time.Time `gorm:"not null"`
	RevokedAt *time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time `gorm:"index"`
}

func (RefreshToken) TableName() string {
	return "refresh_tokens"
}
