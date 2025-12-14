package mappers

import (
	"go_auth/src/domain/entities"
	valueobjects "go_auth/src/domain/value_objects"
	"go_auth/src/infra/persistence/postgres/models"

	"fmt"

	"github.com/google/uuid"
)

type UserMapper struct{}

func (m *UserMapper) ToDomain(u *models.User) (*entities.User, error) {
	if u == nil {
		return nil, nil
	}

	idUUID, err := uuid.Parse(u.ID)
	if err != nil {
		return nil, fmt.Errorf("user mapper: failed to parse User ID '%s': %w", u.ID, err)
	}
	userID := valueobjects.UserID{Value: idUUID}

	emailVO := valueobjects.Email{Value: u.Email}
	pwHashVO := valueobjects.PasswordHash{Value: u.PasswordHash}

	roles := make([]entities.Role, 0, len(u.Roles))
	roleMapper := RoleMapper{}

	for _, rModel := range u.Roles {
		rEntity, err := roleMapper.ToDomain(&rModel)
		if err != nil {
			return nil, fmt.Errorf("user mapper: failed to map nested role: %w", err)
		}
		roles = append(roles, *rEntity)
	}

	return &entities.User{
		ID:           userID,
		Email:        emailVO,
		PasswordHash: pwHashVO,
		IsActive:     u.IsActive,
		Roles:        roles,
		CreatedAt:    u.CreatedAt,
		UpdatedAt:    u.UpdatedAt,
	}, nil
}

func (m *UserMapper) ToModel(u *entities.User) (*models.User, error) {
	if u == nil {
		return nil, nil
	}

	userModelID := u.ID.Value.String()

	rolesModel := make([]models.Role, 0, len(u.Roles))
	roleMapper := RoleMapper{}

	for _, rEntity := range u.Roles {
		rModel, err := roleMapper.ToModel(&rEntity)
		if err != nil {
			return nil, fmt.Errorf("user mapper: failed to map nested role model: %w", err)
		}
		rolesModel = append(rolesModel, *rModel)
	}

	return &models.User{
		ID:           userModelID,
		Email:        u.Email.Value,
		PasswordHash: u.PasswordHash.Value,
		IsActive:     u.IsActive,
		Roles:        rolesModel,
	}, nil
}
