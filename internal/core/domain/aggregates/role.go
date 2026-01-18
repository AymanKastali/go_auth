package aggregates

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

func (e *Role) ID() valueobjects.RoleID {
	return e.id
}

func (e *Role) Name() string {
	return strings.ToLower(e.name)
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

func NewRole(
	roleID valueobjects.RoleID,
	name string,
	currentTime time.Time,
) (*Role, error) {
	if roleID.IsEmpty() {
		return nil, derr.ErrRoleIDRequired()
	}

	trimmedName := strings.TrimSpace(name)
	if trimmedName == "" {
		return nil, derr.ErrRoleNameRequired()
	}

	if currentTime.IsZero() {
		return nil, derr.ErrCurrentTimeRequired()
	}

	return &Role{
		id:        roleID,
		name:      strings.ToLower(trimmedName),
		createdAt: currentTime,
		updatedAt: currentTime,
	}, nil
}
func ReconstituteRole(
	roleID valueobjects.RoleID,
	name string,
	createdAt, updatedAt time.Time,
	deletedAt *time.Time,
) *Role {
	return &Role{
		id:        roleID,
		name:      strings.ToLower(strings.TrimSpace(name)),
		createdAt: createdAt,
		updatedAt: updatedAt,
		deletedAt: deletedAt,
	}
}
