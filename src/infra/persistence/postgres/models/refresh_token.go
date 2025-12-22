package models

import (
	"time"

	"gorm.io/gorm"
)

type RefreshToken struct {
	gorm.Model
	ID        string    `gorm:"primaryKey;type:uuid"`
	UserID    string    `gorm:"not null;index"`
	User      User      `gorm:"foreignKey:UserID"` // optional struct relation
	Token     string    `gorm:"not null"`
	ExpiresAt time.Time `gorm:"not null"`
	RevokedAt *time.Time
}

func (RefreshToken) TableName() string {
	return "refresh_tokens"
}
