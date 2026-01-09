package mappers

import (
	"fmt"

	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/adapters/persistence/postgres/pgerr"
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/valueobjects"
)

type UserMapper struct{}

func NewUserMapper() *UserMapper {
	return &UserMapper{}
}

func (m *UserMapper) ToDomain(u *models.User) (*aggregates.User, error) {
	entity := "User"

	if u == nil {
		return nil, nil
	}

	// 1. Map ID
	userID, err := valueobjects.UserIDFromString(u.ID)
	if err != nil {
		return nil, pgerr.NewDataCorruptionErr(entity, u.ID, "ID", err)
	}

	// 2. Map Email
	emailVO, err := valueobjects.NewEmail(u.Email)
	if err != nil {
		return nil, pgerr.NewDataCorruptionErr(entity, u.ID, "Email", err)
	}

	// 3. Map Password Hash (Missing in your code)
	pwHashVO := valueobjects.NewHashedPassword(u.HashedPassword)

	// 4. Map Status
	var status valueobjects.UserStatus
	switch u.Status {
	case string(valueobjects.UserActive):
		status = valueobjects.UserActive
	case string(valueobjects.UserInactive):
		status = valueobjects.UserInactive
	default:
		return nil, pgerr.NewDataCorruptionErr(entity, u.ID, "Status", fmt.Errorf("unknown: %s", u.Status))
	}

	// 5. Map Roles (The reason roles were missing)
	roleIDs := make([]valueobjects.RoleID, len(u.Roles))
	for i, r := range u.Roles {
		rid, err := valueobjects.RoleIDFromString(r.ID)
		if err != nil {
			return nil, pgerr.NewDataCorruptionErr(entity, u.ID, "RoleID", err)
		}
		roleIDs[i] = rid
	}

	// 6. Reconstitute Aggregate
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
		return nil, pgerr.NewDataCorruptionErr(entity, u.ID, "Aggregate", err)
	}

	return user, nil
}

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
