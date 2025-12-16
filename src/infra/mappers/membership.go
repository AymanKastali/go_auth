package mappers

import (
	"fmt"

	"go_auth/src/domain/entities"
	valueobjects "go_auth/src/domain/value_objects"
	"go_auth/src/infra/persistence/postgres/models"

	"github.com/google/uuid"
)

type MembershipMapper struct{}

func (m *MembershipMapper) ToDomain(mm *models.Membership) (*entities.Membership, error) {
	if mm == nil {
		return nil, nil
	}

	id, err := uuid.Parse(mm.ID)
	if err != nil {
		return nil, fmt.Errorf("membership mapper: invalid id: %w", err)
	}

	userID, err := uuid.Parse(mm.UserID)
	if err != nil {
		return nil, fmt.Errorf("membership mapper: invalid user id: %w", err)
	}

	orgID, err := uuid.Parse(mm.OrganizationID)
	if err != nil {
		return nil, fmt.Errorf("membership mapper: invalid org id: %w", err)
	}

	return &entities.Membership{
		ID:             valueobjects.MembershipID{Value: id},
		UserID:         valueobjects.UserID{Value: userID},
		OrganizationID: valueobjects.OrganizationID{Value: orgID},
		Role:           valueobjects.Role(mm.Role),
		Status:         valueobjects.MembershipStatus(mm.Status),
		CreatedAt:      mm.CreatedAt,
		UpdatedAt:      mm.UpdatedAt,
		DeletedAt:      &mm.DeletedAt.Time,
	}, nil
}

func (m *MembershipMapper) ToModel(e *entities.Membership) *models.Membership {
	return &models.Membership{
		ID:             e.ID.Value.String(),
		UserID:         e.UserID.Value.String(),
		OrganizationID: e.OrganizationID.Value.String(),
		Role:           string(e.Role),
		Status:         string(e.Status),
	}
}
