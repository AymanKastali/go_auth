package models

import (
	"go_auth/internal/adapters/persistence/postgres/pgerr"
	"go_auth/internal/core/domain/ports"
	"time"
)

type Role struct {
	ID        string `gorm:"primaryKey;type:uuid"`
	Name      string `gorm:"uniqueIndex;not null"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time `gorm:"index"`
}

func (Role) TableName() string {
	return "roles"
}

func (m *Role) Validate(idSvc ports.IIDService) error {
	// 1. Identity Integrity
	if !idSvc.IsValid(m.ID) {
		return pgerr.NewIntegrityError("Role", "ID", m.ID)
	}

	// 2. Technical Integrity
	if m.Name == "" {
		return pgerr.NewIntegrityError("Role", "Name", "empty")
	}

	return nil
}
