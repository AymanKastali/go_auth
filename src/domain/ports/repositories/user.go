package repositories

import (
	"go_auth/src/domain/entities"
	value_objects "go_auth/src/domain/value_objects"
)

type UserRepositoryPort interface {
	Save(user *entities.User) error
	GetByID(id value_objects.UserID) (*entities.User, error)
	GetByEmail(email value_objects.Email) (*entities.User, error)
	// AddRole(userID value_objects.UserID, role *entities.Role) error
	// RemoveRole(userID value_objects.UserID, roleID value_objects.RoleID) error
}
