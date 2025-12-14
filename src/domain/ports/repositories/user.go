package repositories

import (
	"go_auth/src/domain/entities"
	valueobjects "go_auth/src/domain/value_objects"
)

type UserRepositoryPort interface {
	Save(user *entities.User) error
	GetByID(id valueobjects.UserID) (*entities.User, error)
	GetByEmail(email valueobjects.Email) (*entities.User, error)
	// AddRole(userID valueobjects.UserID, role *entities.Role) error
	// RemoveRole(userID valueobjects.UserID, roleID valueobjects.RoleID) error
}
