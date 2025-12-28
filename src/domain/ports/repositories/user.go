package repositories

import (
	"go_auth/src/domain/entities"
	"go_auth/src/domain/value_objects"
)

type UserRepositoryPort interface {
	Save(user *entities.User) error
	Update(user *entities.User) error
	GetByID(id value_objects.UserID) (*entities.User, error)
	GetByEmail(email value_objects.Email) (*entities.User, error)
}
