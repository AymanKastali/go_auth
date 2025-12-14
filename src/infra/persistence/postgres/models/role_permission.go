package models

import "time"

type RolePermission struct {
	RoleID       string `gorm:"primaryKey" json:"role_id"`       // Foreign Key to Role
	PermissionID string `gorm:"primaryKey" json:"permission_id"` // Foreign Key to Permission

	// Optional: Any additional data about the assignment
	AssignedBy string    `json:"assigned_by"`
	AssignedAt time.Time `gorm:"default:CURRENT_TIMESTAMP" json:"assigned_at"`
}

func (RolePermission) TableName() string {
	return "role_permissions" // Matches the 'many2many:role_permissions' tag above
}
