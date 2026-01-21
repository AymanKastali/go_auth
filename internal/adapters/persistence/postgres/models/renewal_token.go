package models

import (
	"time"
)

type RenewalToken struct {
	ID        string    `gorm:"primaryKey;type:uuid"`
	UserID    string    `gorm:"not null;index"`
	User      User      `gorm:"foreignKey:UserID"`
	DeviceID  string    `gorm:"type:uuid;not null;index"`
	Device    Device    `gorm:"foreignKey:DeviceID"`
	Hash      string    `gorm:"not null;uniqueIndex"`
	ExpiresAt time.Time `gorm:"not null"`
	RevokedAt *time.Time
	CreatedAt time.Time
}

func (RenewalToken) TableName() string {
	return "renewal_tokens"
}
