package mappers

import (
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/valueobjects"
	"time"
)

type RoleMapper struct{}

func NewRoleMapper() *RoleMapper { return &RoleMapper{} }

func (m *RoleMapper) ToDomain(model *models.Role) *aggregates.Role {
	if model == nil {
		return nil
	}

	var deletedAt *valueobjects.Timepoint
	if model.DeletedAt != nil {
		tp := valueobjects.ReconstituteTimepoint(*model.DeletedAt)
		deletedAt = &tp
	}

	return aggregates.ReconstituteRole(
		valueobjects.ReconstituteRoleID(model.ID),
		model.Name,
		valueobjects.ReconstituteTimepoint(model.CreatedAt),
		valueobjects.ReconstituteTimepoint(model.UpdatedAt),
		deletedAt,
	)
}

func (m *RoleMapper) ToModel(entity *aggregates.Role) *models.Role {
	if entity == nil {
		return nil
	}

	var deletedAtPtr *time.Time
	if entity.DeletedAt() != nil {
		t := entity.DeletedAt().Value()
		deletedAtPtr = &t
	}

	return &models.Role{
		ID:        entity.ID().Value(),
		Name:      entity.Name(),
		CreatedAt: entity.CreatedAt().Value(),
		UpdatedAt: entity.UpdatedAt().Value(),
		DeletedAt: deletedAtPtr,
	}
}
