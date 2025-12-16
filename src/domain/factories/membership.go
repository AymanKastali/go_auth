package factories

import (
	"errors"

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
) (*entities.Membership, error) {

	if membershipID.IsZero() {
		return nil, errors.New("membership id is required")
	}
	if userID.IsZero() {
		return nil, errors.New("user id is required")
	}
	if organizationID.IsZero() {
		return nil, errors.New("organization id is required")
	}
	if role == "" {
		return nil, errors.New("membership role is required")
	}
	if status == "" {
		return nil, errors.New("membership status is required")
	}

	return &entities.Membership{
		ID:             membershipID,
		UserID:         userID,
		OrganizationID: organizationID,
		Role:           role,
		Status:         status,
	}, nil
}
