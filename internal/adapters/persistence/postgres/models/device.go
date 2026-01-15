package models

import (
	"go_auth/internal/adapters/persistence/postgres/pgerr"
	"go_auth/internal/core/domain/ports"
	"time"
)

type Device struct {
	ID         string  `gorm:"primaryKey;type:uuid"`
	UserID     string  `gorm:"not null;index"`
	User       User    `gorm:"foreignKey:UserID"`
	Name       *string `gorm:"type:varchar(100)"`
	UserAgent  *string `gorm:"type:text"`
	IPAddress  *string `gorm:"type:varchar(45)"`
	IsActive   bool    `gorm:"not null;default:true"`
	LastSeenAt time.Time
	RevokedAt  *time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
	DeletedAt  *time.Time `gorm:"index"`
}

func (Device) TableName() string {
	return "devices"
}

func (d *Device) Validate(idSvc ports.IIDService) error {
	// 1. Primary Identity
	if !idSvc.IsValid(d.ID) {
		return pgerr.NewIntegrityError("Device", "ID", d.ID)
	}

	// 2. Foreign Key Integrity
	if !idSvc.IsValid(d.UserID) {
		return pgerr.NewIntegrityError("Device", "UserID", d.UserID)
	}

	// 3. Optional: Business field constraints (Technical check)
	if d.IsActive && d.RevokedAt != nil {
		return pgerr.NewIntegrityError("Device", "RevokedAt", "active device cannot have revocation date")
	}

	return nil
}
