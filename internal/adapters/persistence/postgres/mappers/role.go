package mappers

import (
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/valueobjects"
)

type RoleMapper struct{}

func NewRoleMapper() *RoleMapper { return &RoleMapper{} }

func (m *RoleMapper) ToDomain(model *models.Role) *aggregates.Role {
	if model == nil {
		return nil
	}

	return aggregates.ReconstituteRole(
		valueobjects.ReconstituteRoleID(model.ID),
		model.Name,
		model.CreatedAt,
		model.UpdatedAt,
		model.DeletedAt,
	)
}

func (m *RoleMapper) ToModel(entity *aggregates.Role) *models.Role {
	if entity == nil {
		return nil
	}

	return &models.Role{
		ID:        entity.ID().Value(),
		Name:      entity.Name(),
		CreatedAt: entity.CreatedAt(),
		UpdatedAt: entity.UpdatedAt(),
		DeletedAt: entity.DeletedAt(),
	}
}
