package entities

import (
	"errors"
	"go_auth/src/domain/value_objects"
	"time"
)

type User struct {
	ID           value_objects.UserId
	Email        value_objects.Email
	PasswordHash value_objects.PasswordHash
	Status       value_objects.UserStatus
	Roles        []value_objects.Role
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    *time.Time
}

func (e *User) touch() {
	e.UpdatedAt = time.Now().UTC()
}

func (e *User) Activate() error {
	if e.Status == value_objects.UserActive {
		return errors.New("user is already active")
	}
	e.Status = value_objects.UserActive
	e.touch()
	return nil
}

func (e *User) Deactivate() error {
	if e.Status == value_objects.UserInactive {
		return errors.New("user is already inactive")
	}
	e.Status = value_objects.UserInactive
	e.touch()
	return nil
}

func (e *User) MarkDeleted() {
	now := time.Now().UTC()
	e.DeletedAt = &now
	e.touch()
}
