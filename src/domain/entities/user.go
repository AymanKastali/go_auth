package entities

import (
	valueobjects "go_auth/src/domain/value_objects"

	"github.com/google/uuid"
)

type User struct {
	ID           uuid.UUID
	Email        valueobjects.Email
	PasswordHash valueobjects.PasswordHash
	IsActive     bool
}

func NewUser(id uuid.UUID, email valueobjects.Email, hash valueobjects.PasswordHash) *User {
	return &User{
		ID:           id,
		Email:        email,
		PasswordHash: hash,
		IsActive:     true,
	}
}

func (u *User) Deactivate() {
	u.IsActive = false
}
