package factories

import (
	"go_auth/src/domain/entities"
	valueobjects "go_auth/src/domain/value_objects"
	"time"
)

type UserFactory struct{}

func (f *UserFactory) New(
	email valueobjects.Email,
	passwordHash valueobjects.PasswordHash,
	roles []entities.Role,
	isActive bool,
) *entities.User {
	now := time.Now().UTC()
	idFactory := IDFactory{}
	return &entities.User{
		ID:           idFactory.NewUserID(),
		Email:        email,
		PasswordHash: passwordHash,
		Roles:        roles,
		IsActive:     isActive,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

}
