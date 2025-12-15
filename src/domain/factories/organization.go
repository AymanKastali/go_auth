package factories

import (
	"go_auth/src/domain/entities"
	valueobjects "go_auth/src/domain/value_objects"
)

type OrganizationFactory struct{}

func (f *OrganizationFactory) New(
	organizationID valueobjects.OrganizationID,
	name string,
	ownerUserID valueobjects.UserID,
	status valueobjects.OrganizationStatus,
) *entities.Organization {
	return &entities.Organization{
		ID:          organizationID,
		Name:        name,
		OwnerUserID: ownerUserID,
		Status:      status,
	}

}
