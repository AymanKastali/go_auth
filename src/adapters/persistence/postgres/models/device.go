package models

import (
	"time"

	"gorm.io/gorm"
)

type Device struct {
	gorm.Model
	ID         string  `gorm:"primaryKey;type:uuid"`
	UserId     string  `gorm:"not null;index"`
	User       User    `gorm:"foreignKey:UserId"` // optional struct relation
	Name       *string `gorm:"type:varchar(100)"`
	UserAgent  *string `gorm:"type:text"`
	IPAddress  *string `gorm:"type:varchar(45)"`
	IsActive   bool    `gorm:"not null;default:true"`
	LastSeenAt *time.Time
	RevokedAt  *time.Time
}

func (Device) TableName() string {
	return "devices"
}
