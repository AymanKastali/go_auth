package entities

import (
	"errors"
	valueobjects "go_auth/src/domain/value_objects"
	"time"
)

type User struct {
	ID           valueobjects.UserID
	Email        valueobjects.Email
	PasswordHash valueobjects.PasswordHash
	Status       valueobjects.UserStatus
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    *time.Time
}

func (u *User) touch() {
	u.UpdatedAt = time.Now().UTC()
}

func (u *User) Activate() error {
	if u.Status == valueobjects.UserActive {
		return errors.New("user is already active")
	}
	u.Status = valueobjects.UserActive
	u.touch()
	return nil
}

func (u *User) Deactivate() error {
	if u.Status == valueobjects.UserInactive {
		return errors.New("user is already inactive")
	}
	u.Status = valueobjects.UserInactive
	u.touch()
	return nil
}
