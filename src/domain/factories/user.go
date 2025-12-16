package factories

import (
	"errors"

	"go_auth/src/domain/entities"
	valueobjects "go_auth/src/domain/value_objects"
)

type UserFactory struct{}

func (f *UserFactory) New(
	id valueobjects.UserID,
	email valueobjects.Email,
	passwordHash valueobjects.PasswordHash,
	status valueobjects.UserStatus,
) (*entities.User, error) {

	if id.IsZero() {
		return nil, errors.New("user id is required")
	}
	if email.Value == "" {
		return nil, errors.New("email is required")
	}
	if passwordHash.Value == "" {
		return nil, errors.New("password hash is required")
	}
	if status == "" {
		return nil, errors.New("user status is required")
	}

	return &entities.User{
		ID:           id,
		Email:        email,
		PasswordHash: passwordHash,
		Status:       status,
	}, nil
}
