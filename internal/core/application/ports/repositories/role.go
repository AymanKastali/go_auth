package repositories

import (
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/valueobjects"
)

type RoleRepositoryPort interface {
	Save(role *aggregates.Role) error
	GetByID(id valueobjects.RoleID) (*aggregates.Role, error)
	GetByName(name string) (*aggregates.Role, error)
	GetAll() ([]*aggregates.Role, error)
}
