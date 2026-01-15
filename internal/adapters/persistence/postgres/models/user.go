package models

import (
	"go_auth/internal/adapters/persistence/postgres/pgerr"
	"go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
	"time"
)

type User struct {
	ID             string `gorm:"primaryKey;type:uuid"`
	Email          string `gorm:"uniqueIndex;not null"`
	HashedPassword string `gorm:"not null"`
	Status         string `gorm:"type:varchar(20);not null"`
	Roles          []Role `gorm:"many2many:user_roles;"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
	DeletedAt      *time.Time `gorm:"index"`
}

func (User) TableName() string {
	return "users"
}

func (u *User) Validate(
	idService ports.IIDService,
	passService ports.IPasswordService,
) error {
	// 1. Identity
	if !idService.IsValid(u.ID) {
		return pgerr.NewIntegrityError("User", "ID", u.ID)
	}

	// 2. Password Hash Integrity
	if !passService.IsValidHash(u.HashedPassword) {
		return pgerr.NewIntegrityError("User", "HashedPassword", "invalid_bcrypt_format")
	}

	// 3. Status/Enum
	if !valueobjects.UserStatus(u.Status).IsValid() {
		return pgerr.NewIntegrityError("User", "Status", u.Status)
	}

	// 4. Email
	if u.Email == "" {
		return pgerr.NewIntegrityError("User", "Email", "empty")
	}

	// 5. Roles
	for _, role := range u.Roles {
		if !idService.IsValid(role.ID) {
			return pgerr.NewIntegrityError("UserRole", "RoleID", role.ID)
		}
	}

	return nil
}
