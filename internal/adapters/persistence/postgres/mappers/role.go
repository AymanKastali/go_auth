package mappers

import (
	"fmt"
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/valueobjects"
)

type RoleMapper struct{}

func NewRoleMapper() *RoleMapper {
	return &RoleMapper{}
}

// ToDomain converts a GORM Role model to domain Role entity
func (m *RoleMapper) ToDomain(r *models.Role) (*aggregates.Role, error) {
	if r == nil {
		return nil, nil
	}

	roleID, err := valueobjects.RoleIDFromString(r.ID)
	if err != nil {
		return nil, fmt.Errorf("invalid Role ID '%s': %w", r.ID, err)
	}

	role, err := aggregates.ReconstituteRole(
		roleID,
		r.Name,
		r.CreatedAt,
		r.UpdatedAt,
		r.DeletedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to reconstitute role: %w", err)
	}

	return role, nil
}

// ToModel converts a domain Role entity to GORM Role model
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
