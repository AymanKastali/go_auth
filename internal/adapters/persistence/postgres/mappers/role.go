package mappers

import (
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/adapters/persistence/postgres/pgerr"
	"go_auth/internal/core/application/interfaces"
	"go_auth/internal/core/domain/aggregates"
)

type RoleMapper struct {
	uuidParser interfaces.IUUIDParserService
}

var _ IRoleMapper = (*RoleMapper)(nil)

func NewRoleMapper(
	p interfaces.IUUIDParserService,
) IRoleMapper {
	return &RoleMapper{
		uuidParser: p,
	}
}

func (m *RoleMapper) ToDomain(r *models.Role) (*aggregates.Role, error) {
	entity := "Role"
	if r == nil {
		return nil, nil
	}

	roleID, err := m.uuidParser.ParseRoleID(r.ID)
	if err != nil {
		return nil, pgerr.NewDataCorruptionErr(entity, r.ID, err)
	}

	role, err := aggregates.ReconstituteRole(
		roleID,
		r.Name,
		r.CreatedAt,
		r.UpdatedAt,
		r.DeletedAt,
	)
	if err != nil {
		return nil, pgerr.NewDataCorruptionErr(entity, r.ID, err)
	}

	return role, nil
}

func (m *RoleMapper) ToModel(role *aggregates.Role) (*models.Role, error) {
	if role == nil {
		return nil, nil
	}

	return &models.Role{
		ID:        role.ID().Value(),
		Name:      role.Name(),
		CreatedAt: role.CreatedAt(),
		UpdatedAt: role.UpdatedAt(),
		DeletedAt: role.DeletedAt(),
	}, nil
}
