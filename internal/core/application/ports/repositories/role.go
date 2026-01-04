package repositories

import (
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/valueobjects"
)

type RoleRepositoryPort interface {
	Save(role *entities.Role) error
	GetByID(id valueobjects.RoleID) (*entities.Role, error)
	GetByName(name string) (*entities.Role, error)
	GetAll() ([]*entities.Role, error)
}
