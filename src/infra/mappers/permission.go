package mappers

import (
	"go_auth/src/domain/entities"
	valueobjects "go_auth/src/domain/value_objects"
	"go_auth/src/infra/persistence/postgres/models"

	"fmt"

	"github.com/google/uuid"
)

type PermissionMapper struct{}

func (m *PermissionMapper) ToDomain(p *models.Permission) (*entities.Permission, error) {
	if p == nil {
		return nil, nil
	}

	idUUID, err := uuid.Parse(p.ID)
	if err != nil {
		return nil, fmt.Errorf("mapper error: failed to parse Permission ID '%s': %w", p.ID, err)
	}

	permID := valueobjects.PermissionID{
		Value: idUUID,
	}

	return &entities.Permission{
		ID:        permID,
		Key:       p.Key,
		Name:      p.Name,
		Category:  p.Category,
		CreatedAt: p.CreatedAt,
	}, nil
}

func (m *PermissionMapper) ToModel(p *entities.Permission) (*models.Permission, error) {
	if p == nil {
		return nil, nil
	}

	permUUID := p.ID.Value

	permModelID := permUUID.String()

	return &models.Permission{
		ID:       permModelID,
		Key:      p.Key,
		Name:     p.Name,
		Category: p.Category,
	}, nil
}
