package mappers

import (
	"go_auth/src/domain/entities"
	valueobjects "go_auth/src/domain/value_objects"
	"go_auth/src/infra/persistence/postgres/models"

	"fmt"

	"github.com/google/uuid"
)

type RoleMapper struct{}

func (m *RoleMapper) ToDomain(r *models.Role) (*entities.Role, error) {
	if r == nil {
		return nil, nil
	}

	idUUID, err := uuid.Parse(r.ID)
	if err != nil {
		return nil, fmt.Errorf("mapper error: failed to parse Role ID '%s': %w", r.ID, err)
	}

	roleID := valueobjects.RoleID{
		Value: idUUID,
	}

	permissions := make([]entities.Permission, 0, len(r.Permissions))
	permMapper := PermissionMapper{}

	for _, pModel := range r.Permissions {
		pEntity, err := permMapper.ToDomain(&pModel)
		if err != nil {
			return nil, fmt.Errorf("mapper error: failed to map nested permission: %w", err)
		}
		permissions = append(permissions, *pEntity)
	}

	return &entities.Role{
		ID:          roleID,
		Name:        r.Name,
		Description: r.Description,
		Permissions: permissions,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}, nil
}

func (m *RoleMapper) ToModel(r *entities.Role) (*models.Role, error) {
	if r == nil {
		return nil, nil
	}

	roleModelID := r.ID.Value.String()

	permissionsModel := make([]models.Permission, 0, len(r.Permissions))
	permMapper := PermissionMapper{}

	for _, pEntity := range r.Permissions {
		pModel, err := permMapper.ToModel(&pEntity)
		if err != nil {
			return nil, fmt.Errorf("mapper error: failed to map nested permission model: %w", err)
		}
		permissionsModel = append(permissionsModel, *pModel)
	}

	return &models.Role{
		ID:          roleModelID,
		Name:        r.Name,
		Description: r.Description,
		Permissions: permissionsModel,
	}, nil
}
