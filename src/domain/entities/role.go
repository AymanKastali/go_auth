package entities

import (
	"errors"
	valueobjects "go_auth/src/domain/value_objects"
	"time"
)

type Role struct {
	ID          valueobjects.RoleID
	Name        string
	Description string
	Permissions []Permission
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (u *Role) touch() {
	u.UpdatedAt = time.Now().UTC()
}

func (r *Role) AssignPermission(permission *Permission) error {
	if permission == nil {
		return errors.New("cannot assign a nil permission")
	}

	// 1. Enforce Domsain Invariant: Check for duplicate permission
	newPermissionID := permission.ID // Assuming Permission has an ID field
	for i := range r.Permissions {
		if r.Permissions[i].ID == newPermissionID {
			return errors.New("permission is already assigned to this role")
		}
	}

	// 2. Perform Mutation (State Change)
	r.Permissions = append(r.Permissions, *permission)

	// 3. Update Entity State (Audit Trail)
	r.touch()

	return nil
}
