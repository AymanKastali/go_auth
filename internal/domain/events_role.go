package domain

import "time"

// --- RoleCreated ---

type RoleCreated struct {
	occurredAt  time.Time
	aggregateID string
	roleName    string
}

func NewRoleCreated(roleID RoleID, name RoleName, now time.Time) RoleCreated {
	return RoleCreated{
		occurredAt:  now,
		aggregateID: roleID.String(),
		roleName:    name.Name(),
	}
}

func (e RoleCreated) EventName() string     { return "RoleCreated" }
func (e RoleCreated) OccurredAt() time.Time  { return e.occurredAt }
func (e RoleCreated) AggregateID() string    { return e.aggregateID }
func (e RoleCreated) RoleName() string       { return e.roleName }

// --- PermissionAssigned ---

type PermissionAssigned struct {
	occurredAt  time.Time
	aggregateID string
	permission  string
}

func NewPermissionAssigned(roleID RoleID, p Permission, now time.Time) PermissionAssigned {
	return PermissionAssigned{
		occurredAt:  now,
		aggregateID: roleID.String(),
		permission:  p.String(),
	}
}

func (e PermissionAssigned) EventName() string     { return "PermissionAssigned" }
func (e PermissionAssigned) OccurredAt() time.Time  { return e.occurredAt }
func (e PermissionAssigned) AggregateID() string    { return e.aggregateID }
func (e PermissionAssigned) Permission() string     { return e.permission }

// --- PermissionRevoked ---

type PermissionRevoked struct {
	occurredAt  time.Time
	aggregateID string
	permission  string
}

func NewPermissionRevoked(roleID RoleID, p Permission, now time.Time) PermissionRevoked {
	return PermissionRevoked{
		occurredAt:  now,
		aggregateID: roleID.String(),
		permission:  p.String(),
	}
}

func (e PermissionRevoked) EventName() string     { return "PermissionRevoked" }
func (e PermissionRevoked) OccurredAt() time.Time  { return e.occurredAt }
func (e PermissionRevoked) AggregateID() string    { return e.aggregateID }
func (e PermissionRevoked) Permission() string     { return e.permission }
