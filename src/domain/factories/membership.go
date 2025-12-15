package factories

import (
	"go_auth/src/domain/entities"
	valueobjects "go_auth/src/domain/value_objects"
)

type MembershipFactory struct{}

func (f *MembershipFactory) New(
	membershipID valueobjects.MembershipID,
	userID valueobjects.UserID,
	organizationID valueobjects.OrganizationID,
	role valueobjects.Role,
	status valueobjects.MembershipStatus,
) *entities.Membership {
	return &entities.Membership{
		ID:             membershipID,
		UserID:         userID,
		OrganizationID: organizationID,
		Role:           role,
		Status:         status,
	}

}
