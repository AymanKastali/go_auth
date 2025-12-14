package models

import "time"

type UserRole struct {
	// Composite Primary Key linking User and Role
	UserID string `gorm:"primaryKey" json:"user_id"` // Foreign Key to User
	RoleID string `gorm:"primaryKey" json:"role_id"` // Foreign Key to UserRole

	// Optional: Any additional data about the assignment
	AssignedAt time.Time `gorm:"default:CURRENT_TIMESTAMP" json:"assigned_at"`
	AssignedBy string    `json:"assigned_by"` // e.g., Username of the admin who assigned the role
}

// TableName for the user-role join model.
func (UserRole) TableName() string {
	return "user_roles" // Matches the 'many2many:user_role_mappings' tag above
}
