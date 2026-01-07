package repositories

import (
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/valueobjects"
)

type UserRepositoryPort interface {
	Save(user *aggregates.User) error
	Update(user *aggregates.User) error
	GetByID(id valueobjects.UserID) (*aggregates.User, error)
	GetByEmail(email valueobjects.Email) (*aggregates.User, error)
}
