package repositories

import (
	"go_auth/src/domain/entities"
)

type RoleRepositoryPort interface {
	Save(role *entities.Role) error
	// GetByID(id valueobjects.RoleID) (*entities.Role, error)
	// FindByName(name string) (*entities.Role, error)
	// FindAll() ([]*entities.Role, error)
	// AddPermission(roleID valueobjects.RoleID, permission *entities.Permission) error
	// RemovePermission(roleID valueobjects.RoleID, permissionID valueobjects.PermissionID) error
}
