package domain

import (
	"slices"
	"time"
)

// Role is the Aggregate Root for the RBAC context.
type Role struct {
	EventRecorder
	id          RoleID
	name        RoleName
	description string
	permissions []Permission
}

// NewRole enforces business invariants during initial creation.
func NewRole(
	id RoleID,
	name RoleName,
	description string,
	permissions []Permission,
	now time.Time,
) (*Role, error) {
	if id.IsEmpty() {
		return nil, ErrRoleIDRequired
	}
	if name.IsEmpty() {
		return nil, ErrRoleNotRecognized
	}

	r := &Role{
		id:          id,
		name:        name,
		description: description,
		permissions: slices.Clone(permissions),
	}
	r.RecordEvent(NewRoleCreated(id, name, now))
	return r, nil
}

// ReconstituteRole is for Repository use only.
func ReconstituteRole(
	id RoleID,
	name RoleName,
	description string,
	permissions []Permission,
) *Role {
	return &Role{
		id:          id,
		name:        name,
		description: description,
		permissions: slices.Clone(permissions),
	}
}

// --- Behavior ---

func (r *Role) AssignPermission(p Permission, now time.Time) {
	for _, existing := range r.permissions {
		if existing.Equal(p) {
			return // Idempotent
		}
	}
	r.permissions = append(r.permissions, p)
	r.RecordEvent(NewPermissionAssigned(r.id, p, now))
}

func (r *Role) RevokePermission(p Permission, now time.Time) error {
	for i, existing := range r.permissions {
		if existing.Equal(p) {
			r.permissions = append(r.permissions[:i], r.permissions[i+1:]...)
			r.RecordEvent(NewPermissionRevoked(r.id, p, now))
			return nil
		}
	}
	return ErrPermissionNotFound
}

func (r *Role) HasPermission(p Permission) bool {
	for _, existing := range r.permissions {
		if existing.Equal(p) {
			return true
		}
	}
	return false
}

// --- Getters ---

func (r *Role) ID() RoleID                { return r.id }
func (r *Role) Name() RoleName            { return r.name }
func (r *Role) Description() string       { return r.description }
func (r *Role) Permissions() []Permission { return slices.Clone(r.permissions) }
func (r *Role) PermissionStrings() []string {
	result := make([]string, len(r.permissions))
	for i, p := range r.permissions {
		result[i] = p.String()
	}
	return result
}
