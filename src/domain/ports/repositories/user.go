package repositories

import (
	"go_auth/src/domain/entities"
	valueobjects "go_auth/src/domain/value_objects"

	"github.com/google/uuid"
)

type UserRepository interface {
	GetByID(id uuid.UUID) (*entities.User, error)
	GetByEmail(email valueobjects.Email) (*entities.User, error)
	Save(user *entities.User) error
}
