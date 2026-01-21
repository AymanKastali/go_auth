package aggregates

import (
	"go_auth/internal/core/domain/derr"
	"go_auth/internal/core/domain/valueobjects"
	"strings"
)

type Role struct {
	id        valueobjects.RoleID
	name      string
	createdAt valueobjects.Timepoint
	updatedAt valueobjects.Timepoint
	deletedAt *valueobjects.Timepoint
}

func (e *Role) ID() valueobjects.RoleID            { return e.id }
func (e *Role) Name() string                       { return strings.ToLower(e.name) }
func (e *Role) CreatedAt() valueobjects.Timepoint  { return e.createdAt }
func (e *Role) UpdatedAt() valueobjects.Timepoint  { return e.updatedAt }
func (e *Role) DeletedAt() *valueobjects.Timepoint { return e.deletedAt }

func NewRole(
	roleID valueobjects.RoleID,
	name string,
	now valueobjects.Timepoint,
) (*Role, error) {
	if roleID.IsEmpty() {
		return nil, derr.ErrRoleIDRequired()
	}

	trimmedName := strings.TrimSpace(name)
	if trimmedName == "" {
		return nil, derr.ErrRoleNameRequired()
	}

	if now.IsZero() {
		return nil, derr.ErrCurrentTimeRequired()
	}

	return &Role{
		id:        roleID,
		name:      strings.ToLower(trimmedName),
		createdAt: now,
		updatedAt: now,
	}, nil
}
func ReconstituteRole(
	roleID valueobjects.RoleID,
	name string,
	createdAt, updatedAt valueobjects.Timepoint,
	deletedAt *valueobjects.Timepoint,
) *Role {
	return &Role{
		id:        roleID,
		name:      strings.ToLower(strings.TrimSpace(name)),
		createdAt: createdAt,
		updatedAt: updatedAt,
		deletedAt: deletedAt,
	}
}
