package repositories

import (
	"go_auth/src/domain/entities"
	"go_auth/src/domain/value_objects"
)

type UserRepositoryPort interface {
	Save(user *entities.User) error
	GetByID(id value_objects.UserId) (*entities.User, error)
	GetByEmail(email value_objects.Email) (*entities.User, error)
	// AddRole(userId value_objects.UserId, role *entities.Role) error
	// RemoveRole(userId value_objects.UserId, roleID value_objects.RoleID) error
}
