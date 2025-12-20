package mappers

import (
	"fmt"

	"go_auth/src/domain/entities"
	value_objects "go_auth/src/domain/value_objects"
	"go_auth/src/infra/persistence/postgres/models"

	"github.com/google/uuid"
)

type UserMapper struct{}

// ToDomain maps the GORM model to the domain entity
func (m *UserMapper) ToDomain(u *models.User) (*entities.User, error) {
	if u == nil {
		return nil, nil
	}

	idUUID, err := uuid.Parse(u.ID)
	if err != nil {
		return nil, fmt.Errorf("user mapper: failed to parse User ID '%s': %w", u.ID, err)
	}
	userID := value_objects.UserID{Value: idUUID}

	emailVO := value_objects.Email{Value: u.Email}
	pwHashVO := value_objects.PasswordHash{Value: u.PasswordHash}

	// Map string status to UserStatus enum
	var status value_objects.UserStatus
	switch u.Status {
	case string(value_objects.UserActive):
		status = value_objects.UserActive
	case string(value_objects.UserInactive):
		status = value_objects.UserInactive
	default:
		return nil, fmt.Errorf("user mapper: unknown status '%s'", u.Status)
	}

	return &entities.User{
		ID:           userID,
		Email:        emailVO,
		PasswordHash: pwHashVO,
		Status:       status,
		CreatedAt:    u.CreatedAt,
		UpdatedAt:    u.UpdatedAt,
		DeletedAt:    &u.DeletedAt.Time,
	}, nil
}

// ToModel maps the domain entity to the GORM model
func (m *UserMapper) ToModel(u *entities.User) (*models.User, error) {
	if u == nil {
		return nil, nil
	}

	return &models.User{
		ID:           u.ID.Value.String(),
		Email:        u.Email.Value,
		PasswordHash: u.PasswordHash.Value,
		Status:       string(u.Status), // map enum to string
	}, nil
}
