package factories

import (
	"errors"

	"go_auth/src/domain/entities"
	value_objects "go_auth/src/domain/value_objects"
)

type UserFactory struct{}

func (f *UserFactory) New(
	id value_objects.UserID,
	email value_objects.Email,
	passwordHash value_objects.PasswordHash,
	status value_objects.UserStatus,
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
