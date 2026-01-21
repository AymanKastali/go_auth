package models

import (
	"time"
)

type Device struct {
	ID          string  `gorm:"primaryKey;type:uuid"`
	Fingerprint string  `gorm:"type:varchar(255);uniqueIndex"`
	UserID      string  `gorm:"not null;index"`
	User        User    `gorm:"foreignKey:UserID"`
	Name        *string `gorm:"type:varchar(100)"`
	UserAgent   *string `gorm:"type:text"`
	IPAddress   *string `gorm:"type:varchar(45)"`
	IsActive    bool    `gorm:"not null;default:true"`
	LastSeenAt  time.Time
	RevokedAt   *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   *time.Time `gorm:"index"`
}

func (Device) TableName() string {
	return "devices"
}
