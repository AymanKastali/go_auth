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

func NewRole(
	roleID valueobjects.RoleID,
	name string,
	now time.Time,
) (*Role, error) {
	if roleID.IsEmpty() {
		return nil, derr.NewValidation.RequiredRoleID()
	}

	if strings.TrimSpace(name) == "" {
		return nil, derr.NewValidation.RequiredName()
	}

	if now.IsZero() {
		return nil, derr.NewValidation.RequiredNow()
	}

	return &Role{
		id:        roleID,
		name:      name,
		createdAt: now,
		updatedAt: now,
	}, nil
}

func ReconstituteRole(
	roleID valueobjects.RoleID,
	name string,
	createdAt, updatedAt time.Time,
	deletedAt *time.Time,
) (*Role, error) {
	if roleID.IsEmpty() {
		return nil, derr.NewValidation.RequiredRoleID()
	}

	if strings.TrimSpace(name) == "" {
		return nil, derr.NewValidation.RequiredName()
	}

	if createdAt.IsZero() {
		return nil, derr.NewValidation.RequiredCreatedAt()
	}

	if updatedAt.IsZero() {
		return nil, derr.NewValidation.RequiredUpdatedAt()
	}

	return &Role{
		id:        roleID,
		name:      name,
		createdAt: createdAt,
		updatedAt: updatedAt,
		deletedAt: deletedAt,
	}, nil
}
