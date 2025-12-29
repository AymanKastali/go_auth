package mappers

import (
	"fmt"

	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/domain/entities"
	"go_auth/internal/domain/valueobjects"

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

	userID, err := m.uuidMapper.UserIdFromString(u.ID)
	if err != nil {
		return nil, fmt.Errorf("user mapper: invalid User ID '%s': %w", u.ID, err)
	}

	emailVO := valueobjects.Email{Value: u.Email}
	pwHashVO := valueobjects.PasswordHash{Value: u.PasswordHash}

	var status valueobjects.UserStatus
	switch u.Status {
	case string(valueobjects.UserActive):
		status = valueobjects.UserActive
	case string(valueobjects.UserInactive):
		status = valueobjects.UserInactive
	default:
		return nil, fmt.Errorf("user mapper: unknown status '%s'", u.Status)
	}

	roles := make([]valueobjects.Role, len(u.Roles))
	for i, r := range u.Roles {
		roles[i] = valueobjects.Role(r)
	}

	return &entities.User{
		ID:           userID,
		Email:        emailVO,
		PasswordHash: pwHashVO,
		Status:       status,
		Roles:        roles,
		CreatedAt:    u.CreatedAt,
		UpdatedAt:    u.UpdatedAt,
		DeletedAt:    u.DeletedAt,
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
