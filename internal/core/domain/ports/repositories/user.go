package repositories

import (
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/valueobjects"
)

type UserRepositoryPort interface {
	Save(user *entities.User) error
	Update(user *entities.User) error
	GetByID(id valueobjects.UserID) (*entities.User, error)
	GetByEmail(email valueobjects.Email) (*entities.User, error)
}
