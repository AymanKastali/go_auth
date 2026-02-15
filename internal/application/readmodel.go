package application

import "time"

// UserReadModel is a flat projection used by query handlers and adapters.
type UserReadModel struct {
	ID           string
	Email        string
	IsActive     bool
	Roles        []string
	RegisteredAt time.Time
	UpdatedAt    time.Time
}

// RoleReadModel is a flat projection used by query handlers and adapters.
type RoleReadModel struct {
	ID          string
	Name        string
	Description string
	Permissions []string
}

// Zero sentinels for read models.
var (
	ZeroUserReadModel = UserReadModel{}
	ZeroRoleReadModel = RoleReadModel{}
)
