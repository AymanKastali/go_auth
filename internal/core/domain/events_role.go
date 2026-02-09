package domain

// --- RoleCreated ---

type RoleCreated struct {
	occurredAt  Timepoint
	aggregateID string
	roleName    string
}

func NewRoleCreated(roleID RoleID, name RoleName, now Timepoint) RoleCreated {
	return RoleCreated{
		occurredAt:  now,
		aggregateID: roleID.String(),
		roleName:    name.Name(),
	}
}

func (e RoleCreated) EventName() string     { return "RoleCreated" }
func (e RoleCreated) OccurredAt() Timepoint  { return e.occurredAt }
func (e RoleCreated) AggregateID() string    { return e.aggregateID }
func (e RoleCreated) RoleName() string       { return e.roleName }

// --- PermissionAssigned ---

type PermissionAssigned struct {
	occurredAt  Timepoint
	aggregateID string
	permission  string
}

func NewPermissionAssigned(roleID RoleID, p Permission, now Timepoint) PermissionAssigned {
	return PermissionAssigned{
		occurredAt:  now,
		aggregateID: roleID.String(),
		permission:  p.String(),
	}
}

func (e PermissionAssigned) EventName() string     { return "PermissionAssigned" }
func (e PermissionAssigned) OccurredAt() Timepoint  { return e.occurredAt }
func (e PermissionAssigned) AggregateID() string    { return e.aggregateID }
func (e PermissionAssigned) Permission() string     { return e.permission }

// --- PermissionRevoked ---

type PermissionRevoked struct {
	occurredAt  Timepoint
	aggregateID string
	permission  string
}

func NewPermissionRevoked(roleID RoleID, p Permission, now Timepoint) PermissionRevoked {
	return PermissionRevoked{
		occurredAt:  now,
		aggregateID: roleID.String(),
		permission:  p.String(),
	}
}

func (e PermissionRevoked) EventName() string     { return "PermissionRevoked" }
func (e PermissionRevoked) OccurredAt() Timepoint  { return e.occurredAt }
func (e PermissionRevoked) AggregateID() string    { return e.aggregateID }
func (e PermissionRevoked) Permission() string     { return e.permission }
