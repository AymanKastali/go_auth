package repositories

import (
	"go_auth/src/domain/entities"
)

type PermissionRepositoryPort interface {
	Save(permission *entities.Permission) error
	// FindByID(id valueobjects.PermissionID) (*entities.Permission, error)
	// FindByKey(key string) (*entities.Permission, error)
	// FindAll() ([]*entities.Permission, error)
}
