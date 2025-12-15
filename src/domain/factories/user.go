package factories

import (
	"go_auth/src/domain/entities"
	valueobjects "go_auth/src/domain/value_objects"
)

type UserFactory struct{}

func (f *UserFactory) New(
	id valueobjects.UserID,
	email valueobjects.Email,
	passwordHash valueobjects.PasswordHash,
	status valueobjects.UserStatus,
) *entities.User {
	return &entities.User{
		ID:           id,
		Email:        email,
		PasswordHash: passwordHash,
		Status:       status,
	}

}
