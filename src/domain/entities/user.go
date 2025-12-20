package entities

import (
	"errors"
	value_objects "go_auth/src/domain/value_objects"
	"time"
)

type User struct {
	ID           value_objects.UserID
	Email        value_objects.Email
	PasswordHash value_objects.PasswordHash
	Status       value_objects.UserStatus
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    *time.Time
}

func (u *User) touch() {
	u.UpdatedAt = time.Now().UTC()
}

func (u *User) Activate() error {
	if u.Status == value_objects.UserActive {
		return errors.New("user is already active")
	}
	u.Status = value_objects.UserActive
	u.touch()
	return nil
}

func (u *User) Deactivate() error {
	if u.Status == value_objects.UserInactive {
		return errors.New("user is already inactive")
	}
	u.Status = value_objects.UserInactive
	u.touch()
	return nil
}

func (u *User) MarkDeleted() {
	now := time.Now().UTC()
	u.DeletedAt = &now
	u.touch()
}
