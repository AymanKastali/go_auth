package repositories

import (
	"go_auth/src/domain/entities"
	valueobjects "go_auth/src/domain/value_objects"
)

type MembershipRepositoryPort interface {
	Save(m *entities.Membership) error
	GetByID(id valueobjects.MembershipID) (*entities.Membership, error)

	GetByUserAndOrganization(
		userID valueobjects.UserID,
		orgID valueobjects.OrganizationID,
	) (*entities.Membership, error)

	GetByOrganization(orgID valueobjects.OrganizationID) ([]*entities.Membership, error)
}
