package repositories

import (
	"go_auth/src/domain/entities"
	value_objects "go_auth/src/domain/value_objects"
)

type MembershipRepositoryPort interface {
	Save(m *entities.Membership) error
	GetByID(id value_objects.MembershipID) (*entities.Membership, error)

	GetByUserAndOrganization(
		userID value_objects.UserID,
		orgID value_objects.OrganizationID,
	) (*entities.Membership, error)

	GetByOrganization(orgID value_objects.OrganizationID) ([]*entities.Membership, error)
}
