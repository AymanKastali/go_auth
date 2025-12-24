package mappers

import (
	"fmt"

	"go_auth/src/domain/entities"
	"go_auth/src/domain/value_objects"
	"go_auth/src/infra/persistence/postgres/models"

	"gorm.io/datatypes"
)

type UserMapper struct {
	uuidMapper *UUIDMapper
}

func NewUserMapper(
	uuidMapper *UUIDMapper,
) *UserMapper {
	return &UserMapper{
		uuidMapper: uuidMapper,
	}
}

func (m *UserMapper) ToDomain(u *models.User) (*entities.User, error) {
	if u == nil {
		return nil, nil
	}

	userId, err := m.uuidMapper.UserIdFromString(u.ID)
	if err != nil {
		return nil, fmt.Errorf("user mapper: invalid User ID '%s': %w", u.ID, err)
	}

	emailVO := value_objects.Email{Value: u.Email}
	pwHashVO := value_objects.PasswordHash{Value: u.PasswordHash}

	var status value_objects.UserStatus
	switch u.Status {
	case string(value_objects.UserActive):
		status = value_objects.UserActive
	case string(value_objects.UserInactive):
		status = value_objects.UserInactive
	default:
		return nil, fmt.Errorf("user mapper: unknown status '%s'", u.Status)
	}

	roles := make([]value_objects.Role, len(u.Roles))
	for i, r := range u.Roles {
		roles[i] = value_objects.Role(r)
	}

	return &entities.User{
		ID:           userId,
		Email:        emailVO,
		PasswordHash: pwHashVO,
		Status:       status,
		Roles:        roles,
		CreatedAt:    u.CreatedAt,
		UpdatedAt:    u.UpdatedAt,
		DeletedAt:    &u.DeletedAt.Time,
	}, nil
}

func (m *UserMapper) ToModel(u *entities.User) (*models.User, error) {
	if u == nil {
		return nil, nil
	}

	roles := make(datatypes.JSONSlice[string], len(u.Roles))
	for i, r := range u.Roles {
		roles[i] = string(r)
	}

	return &models.User{
		ID:           u.ID.Value.String(),
		Email:        u.Email.Value,
		PasswordHash: u.PasswordHash.Value,
		Status:       string(u.Status),
		Roles:        roles,
	}, nil
}
