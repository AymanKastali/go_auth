package mappers

import (
	"fmt"

	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/valueobjects"

	"gorm.io/datatypes"
)

type UserMapper struct{}

func NewUserMapper() *UserMapper {
	return &UserMapper{}
}

func (m *UserMapper) ToDomain(u *models.User) (*entities.User, error) {
	if u == nil {
		return nil, nil
	}

	userID, err := valueobjects.UserIDFromString(u.ID)
	if err != nil {
		return nil, fmt.Errorf("invalid User ID '%s': %w", u.ID, err)
	}

	emailVO, err := valueobjects.NewEmail(u.Email)
	if err != nil {
		return nil, fmt.Errorf("invalid email '%s': %w", u.Email, err)
	}

	pwHashVO := valueobjects.NewHashedPassword(u.HashedPassword)

	var status valueobjects.UserStatus
	switch u.Status {
	case string(valueobjects.UserActive):
		status = valueobjects.UserActive
	case string(valueobjects.UserInactive):
		status = valueobjects.UserInactive
	default:
		return nil, fmt.Errorf("unknown status '%s'", u.Status)
	}

	roles := make([]valueobjects.Role, len(u.Roles))
	for i, r := range u.Roles {
		roles[i] = valueobjects.Role(r)
	}

	// Use rehydration constructor
	user, err := entities.ReconstituteUser(
		userID,
		emailVO,
		pwHashVO,
		status,
		roles,
		u.CreatedAt,
		u.UpdatedAt,
		u.DeletedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to reconstitute user: %w", err)
	}

	return user, nil
}

func (m *UserMapper) ToModel(u *entities.User) (*models.User, error) {
	if u == nil {
		return nil, nil
	}

	userRoles := u.Roles()
	roles := make(datatypes.JSONSlice[string], len(userRoles))
	for i, r := range userRoles {
		roles[i] = string(r)
	}

	return &models.User{
		ID:             u.ID().String(),
		Email:          u.Email().String(),
		HashedPassword: u.HashedPassword().Value(),
		Status:         string(u.Status()),
		Roles:          roles,
	}, nil
}
