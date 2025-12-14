package entities

import (
	valueobjects "go_auth/src/domain/value_objects"
	"time"
)

type Permission struct {
	ID        valueobjects.PermissionID
	Key       string // Unique identifier for the permission (e.g., "user:write")
	Name      string // Human-readable name (e.g., "Write User Data")
	Category  string // Helps group permissions (e.g., "User Management")
	CreatedAt time.Time
}
