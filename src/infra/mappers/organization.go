package mappers

import (
	"fmt"

	"go_auth/src/domain/entities"
	value_objects "go_auth/src/domain/value_objects"
	"go_auth/src/infra/persistence/postgres/models"

	"github.com/google/uuid"
)

type OrganizationMapper struct{}

func (m *OrganizationMapper) ToDomain(o *models.Organization) (*entities.Organization, error) {
	if o == nil {
		return nil, nil
	}

	orgID, err := uuid.Parse(o.ID)
	if err != nil {
		return nil, fmt.Errorf("organization mapper: invalid org id: %w", err)
	}

	ownerID, err := uuid.Parse(o.OwnerUserID)
	if err != nil {
		return nil, fmt.Errorf("organization mapper: invalid owner user id: %w", err)
	}

	return &entities.Organization{
		ID:          value_objects.OrganizationID{Value: orgID},
		Name:        o.Name,
		OwnerUserID: value_objects.UserID{Value: ownerID},
		Status:      value_objects.OrganizationStatus(o.Status),
		CreatedAt:   o.CreatedAt,
		UpdatedAt:   o.UpdatedAt,
		DeletedAt:   &o.DeletedAt.Time,
	}, nil
}

func (m *OrganizationMapper) ToModel(o *entities.Organization) *models.Organization {
	return &models.Organization{
		ID:          o.ID.Value.String(),
		Name:        o.Name,
		OwnerUserID: o.OwnerUserID.Value.String(),
		Status:      string(o.Status),
	}
}
