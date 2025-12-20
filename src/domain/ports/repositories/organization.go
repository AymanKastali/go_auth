package repositories

import (
	"go_auth/src/domain/entities"
	value_objects "go_auth/src/domain/value_objects"
)

type OrganizationRepositoryPort interface {
	Save(org *entities.Organization) error
	GetByID(id value_objects.OrganizationID) (*entities.Organization, error)
	GetByOwner(ownerID value_objects.UserID) ([]*entities.Organization, error)
}
