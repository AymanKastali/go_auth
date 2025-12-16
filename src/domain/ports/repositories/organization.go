package repositories

import (
	"go_auth/src/domain/entities"
	valueobjects "go_auth/src/domain/value_objects"
)

type OrganizationRepositoryPort interface {
	Save(org *entities.Organization) error
	GetByID(id valueobjects.OrganizationID) (*entities.Organization, error)
	GetByOwner(ownerID valueobjects.UserID) ([]*entities.Organization, error)
}
