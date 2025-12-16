package factories

import (
	"errors"

	"go_auth/src/domain/entities"
	valueobjects "go_auth/src/domain/value_objects"
)

type OrganizationFactory struct{}

func (f *OrganizationFactory) New(
	organizationID valueobjects.OrganizationID,
	name string,
	ownerUserID valueobjects.UserID,
	status valueobjects.OrganizationStatus,
) (*entities.Organization, error) {

	if organizationID.IsZero() {
		return nil, errors.New("organization id is required")
	}
	if name == "" {
		return nil, errors.New("organization name is required")
	}
	if ownerUserID.IsZero() {
		return nil, errors.New("owner user id is required")
	}
	if status == "" {
		return nil, errors.New("organization status is required")
	}

	return &entities.Organization{
		ID:          organizationID,
		Name:        name,
		OwnerUserID: ownerUserID,
		Status:      status,
	}, nil
}
