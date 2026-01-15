package models

import (
	"go_auth/internal/adapters/persistence/postgres/pgerr"
	"go_auth/internal/core/domain/ports"
	"time"
)

type RefreshToken struct {
	ID        string    `gorm:"primaryKey;type:uuid"`
	UserID    string    `gorm:"not null;index"`
	User      User      `gorm:"foreignKey:UserID"`
	DeviceID  string    `gorm:"type:uuid;not null;index"`
	Device    Device    `gorm:"foreignKey:DeviceID"`
	Token     string    `gorm:"not null"`
	ExpiresAt time.Time `gorm:"not null"`
	RevokedAt *time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time `gorm:"index"`
}

func (RefreshToken) TableName() string {
	return "refresh_tokens"
}

func (m *RefreshToken) Validate(idSvc ports.IIDService) error {
	// 1. Primary Identity
	if !idSvc.IsValid(m.ID) {
		return pgerr.NewIntegrityError("RefreshToken", "ID", m.ID)
	}

	// 2. Foreign Keys Integrity
	if !idSvc.IsValid(m.UserID) {
		return pgerr.NewIntegrityError("RefreshToken", "UserID", m.UserID)
	}
	if !idSvc.IsValid(m.DeviceID) {
		return pgerr.NewIntegrityError("RefreshToken", "DeviceID", m.DeviceID)
	}

	// 3. Technical Integrity
	if m.Token == "" {
		return pgerr.NewIntegrityError("RefreshToken", "TokenString", "empty")
	}

	return nil
}
