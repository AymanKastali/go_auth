package mappers

import (
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/adapters/persistence/postgres/pgerr"
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/valueobjects"
)

type RoleMapper struct{}

func NewRoleMapper() *RoleMapper {
	return &RoleMapper{}
}

func (m *RoleMapper) ToDomain(r *models.Role) (*aggregates.Role, error) {
	entity := "Role"
	if r == nil {
		return nil, nil
	}

	roleID, err := valueobjects.RoleIDFromString(r.ID)
	if err != nil {
		return nil, pgerr.NewDataCorruptionErr(entity, r.ID, "ID", err)
	}

	role, err := aggregates.ReconstituteRole(
		roleID,
		r.Name,
		r.CreatedAt,
		r.UpdatedAt,
		r.DeletedAt,
	)
	if err != nil {
		return nil, pgerr.NewDataCorruptionErr(entity, r.ID, "Aggregate", err)
	}

	return role, nil
}

func (m *RoleMapper) ToModel(role *aggregates.Role) (*models.Role, error) {
	if role == nil {
		return nil, nil
	}

	return &models.Role{
		ID:        role.ID().String(),
		Name:      role.Name(),
		CreatedAt: role.CreatedAt(),
		UpdatedAt: role.UpdatedAt(),
		DeletedAt: role.DeletedAt(),
	}, nil
}
