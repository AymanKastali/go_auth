package entities

import (
	valueobjects "go_auth/src/domain/value_objects"
	"time"
)

type User struct {
	id           valueobjects.UserID
	email        valueobjects.Email
	passwordHash valueobjects.PasswordHash
	isActive     bool
	createdAt    time.Time
	updatedAt    time.Time
}

func NewUser(id valueobjects.UserID, email valueobjects.Email, hash valueobjects.PasswordHash) *User {
	return &User{
		id:           id,
		email:        email,
		passwordHash: hash,
		isActive:     true,
		createdAt:    time.Now().UTC(),
		updatedAt:    time.Now().UTC(),
	}
}

func (u *User) ID() valueobjects.UserID {
	return u.id
}

func (u *User) Email() valueobjects.Email {
	return u.email
}
func (u *User) PasswordHash() valueobjects.PasswordHash {
	return u.passwordHash
}

func (u *User) IsActive() bool {
	return u.isActive
}

func (u *User) Deactivate() {
	u.isActive = false
	u.updatedAt = time.Now().UTC()
}

func NewUserFromPersistence(
	id valueobjects.UserID,
	email valueobjects.Email,
	passwordHash valueobjects.PasswordHash,
	isActive bool,
	createdAt, updatedAt time.Time,
) *User {
	return &User{
		id:           id,
		email:        email,
		passwordHash: passwordHash,
		isActive:     isActive,
		createdAt:    createdAt,
		updatedAt:    updatedAt,
	}
}
