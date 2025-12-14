package entities

import (
	valueobjects "go_auth/src/domain/value_objects"
	"time"
)

type User struct {
	ID           valueobjects.UserID
	Email        valueobjects.Email
	PasswordHash valueobjects.PasswordHash
	Roles        []Role
	IsActive     bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    time.Time
}

func (u *User) touch() {
	u.UpdatedAt = time.Now().UTC()
}

// raise error in case of is already active
func (u *User) Activate() {
	u.IsActive = true
	u.touch()
}

func (u *User) Deactivate() {
	u.IsActive = false
	u.touch()
}
