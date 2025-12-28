package factories

import (
	"errors"

	"go_auth/src/domain/entities"
	"go_auth/src/domain/value_objects"
)

type UserFactory struct{}

func (f *UserFactory) New(
	id value_objects.UserID,
	email value_objects.Email,
	passwordHash value_objects.PasswordHash,
	status value_objects.UserStatus,
	roles []value_objects.Role,
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
	if roles == nil {
		roles = []value_objects.Role{}
	}

	return &entities.User{
		ID:           id,
		Email:        email,
		PasswordHash: passwordHash,
		Status:       status,
		Roles:        roles,
	}, nil
}
