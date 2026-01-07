package mappers

import (
	"fmt"

	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/valueobjects"
)

type UserMapper struct{}

func NewUserMapper() *UserMapper {
	return &UserMapper{}
}

// ToDomain converts a GORM User model (with Roles) to a domain entity
func (m *UserMapper) ToDomain(u *models.User) (*aggregates.User, error) {
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

	// Map roles from models.Role → valueobjects.RoleID
	roleIDs := make([]valueobjects.RoleID, len(u.Roles))
	for i, r := range u.Roles {
		roleID, err := valueobjects.RoleIDFromString(r.ID)
		if err != nil {
			return nil, fmt.Errorf("invalid Role ID '%s': %w", r.ID, err)
		}
		roleIDs[i] = roleID
	}

	// Rehydrate the domain User
	user, err := aggregates.ReconstituteUser(
		userID,
		emailVO,
		pwHashVO,
		status,
		roleIDs,
		u.CreatedAt,
		u.UpdatedAt,
		u.DeletedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to reconstitute user: %w", err)
	}

	return user, nil
}

// ToModel converts a domain User entity to a GORM User model
func (m *UserMapper) ToModel(u *aggregates.User) (*models.User, error) {
	if u == nil {
		return nil, nil
	}

	// Convert roleIDs → models.Role for Many-to-Many
	roles := make([]models.Role, len(u.RoleIDs()))
	for i, rid := range u.RoleIDs() {
		roles[i] = models.Role{
			ID: rid.String(),
		}
	}

	return &models.User{
		ID:             u.ID().String(),
		Email:          u.Email().String(),
		HashedPassword: u.HashedPassword().Value(),
		Status:         string(u.Status()),
		Roles:          roles,
		CreatedAt:      u.CreatedAt(),
		UpdatedAt:      u.UpdatedAt(),
		DeletedAt:      u.DeletedAt(),
	}, nil
}
