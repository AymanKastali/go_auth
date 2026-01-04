package entities

import (
	"go_auth/internal/core/domain/derr"
	"go_auth/internal/core/domain/valueobjects"
	"strings"
	"time"
)

type Role struct {
	id        valueobjects.RoleID
	name      string
	createdAt time.Time
	updatedAt time.Time
	deletedAt *time.Time
}

// Getters
func (e *Role) ID() valueobjects.RoleID {
	return e.id
}

func (e *Role) Name() string {
	return e.name
}

func (e *Role) CreatedAt() time.Time {
	return e.createdAt
}

func (e *Role) UpdatedAt() time.Time {
	return e.updatedAt
}

func (e *Role) DeletedAt() *time.Time {
	return e.deletedAt
}

// Constructor
func NewRole(
	roleID valueobjects.RoleID,
	name string,
	nowUTC time.Time,
) (*Role, error) {
	if roleID.IsEmpty() {
		return nil, derr.NewRequiredErr("roleID")
	}

	if strings.TrimSpace(name) == "" {
		return nil, derr.NewRequiredErr("name")
	}

	return &Role{
		id:        roleID,
		name:      name,
		createdAt: nowUTC,
		updatedAt: nowUTC,
	}, nil
}

func ReconstituteRole(
	roleID valueobjects.RoleID,
	name string,
	createdAt, updatedAt time.Time,
	deletedAt *time.Time,
) (*Role, error) {
	return &Role{
		id:        roleID,
		name:      name,
		createdAt: createdAt,
		updatedAt: updatedAt,
		deletedAt: deletedAt,
	}, nil
}
