package mappers

import (
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/core/application/interfaces"
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/valueobjects"
)

type UserMapper struct {
	uuidParser interfaces.IUUIDParserService
}

var _ IUserMapper = (*UserMapper)(nil)

func NewUserMapper(
	uuidParser interfaces.IUUIDParserService,
) IUserMapper {
	return &UserMapper{
		uuidParser: uuidParser,
	}
}

func (m *UserMapper) ToDomain(u *models.User) (*aggregates.User, error) {
	if u == nil {
		return nil, nil
	}

	userID, err := m.uuidParser.ParseUserID(u.ID)
	if err != nil {
		return nil, err
	}

	emailVO := valueobjects.ReconstituteEmail(u.Email)

	pwHashVO := valueobjects.ReconstituteHashedPassword(u.HashedPassword)

	status := valueobjects.UserStatus(u.Status)

	// 5. Map Roles (The reason roles were missing)
	roleIDs := make([]valueobjects.RoleID, len(u.Roles))
	for i, r := range u.Roles {
		roleID, err := m.uuidParser.ParseRoleID(r.ID)
		if err != nil {
			return nil, err
		}
		roleIDs[i] = roleID
	}

	// 6. Reconstitute Aggregate
	user := aggregates.ReconstituteUser(
		userID,
		emailVO,
		pwHashVO,
		status,
		roleIDs,
		u.CreatedAt,
		u.UpdatedAt,
		u.DeletedAt,
	)

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
			ID: rid.Value(),
		}
	}

	return &models.User{
		ID:             u.ID().Value(),
		Email:          u.Email().Value(),
		HashedPassword: u.HashedPassword().Value(),
		Status:         string(u.Status()),
		Roles:          roles,
		CreatedAt:      u.CreatedAt(),
		UpdatedAt:      u.UpdatedAt(),
		DeletedAt:      u.DeletedAt(),
	}, nil
}
