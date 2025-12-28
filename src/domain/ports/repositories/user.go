package repositories

import (
	"go_auth/src/domain/entities"
	"go_auth/src/domain/value_objects"
)

type UserRepositoryPort interface {
	Save(user *entities.User) error
	Update(user *entities.User) error
	GetByID(id value_objects.UserId) (*entities.User, error)
	GetByEmail(email value_objects.Email) (*entities.User, error)
}
