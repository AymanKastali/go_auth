package entities

import (
	"errors"
	"go_auth/internal/domain/valueobjects"
	"slices"
	"time"
)

type User struct {
	ID           valueobjects.UserID
	Email        valueobjects.Email
	PasswordHash valueobjects.PasswordHash
	Status       valueobjects.UserStatus
	Roles        []valueobjects.Role
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    *time.Time
}

func (e *User) touch() {
	e.UpdatedAt = time.Now().UTC()
}

func (e *User) Activate() error {
	if e.Status == valueobjects.UserActive {
		return errors.New("user is already active")
	}
	e.Status = valueobjects.UserActive
	e.touch()
	return nil
}

func (e *User) Deactivate() error {
	if e.Status == valueobjects.UserInactive {
		return errors.New("user is already inactive")
	}
	e.Status = valueobjects.UserInactive
	e.touch()
	return nil
}

func (e *User) MarkDeleted() {
	now := time.Now().UTC()
	e.DeletedAt = &now
	e.touch()
}

func (u *User) AddRole(role valueobjects.Role) {
	if slices.Contains(u.Roles, role) {
		return
	}
	u.Roles = append(u.Roles, role)
}

func (u *User) RemoveRole(role valueobjects.Role) {
	newRoles := []valueobjects.Role{}
	for _, r := range u.Roles {
		if r != role {
			newRoles = append(newRoles, r)
		}
	}
	u.Roles = newRoles
}
