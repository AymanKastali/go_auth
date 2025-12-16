package repositories

import (
	"go_auth/src/domain/entities"
	"go_auth/src/domain/ports/repositories"
	valueobjects "go_auth/src/domain/value_objects"
	"go_auth/src/infra/mappers"
	"go_auth/src/infra/persistence/postgres/models"

	"gorm.io/gorm"
)

type GormOrganizationRepository struct {
	db     *gorm.DB
	mapper mappers.OrganizationMapper
}

var _ repositories.OrganizationRepositoryPort = (*GormOrganizationRepository)(nil)

func NewGormOrganizationRepository(
	db *gorm.DB,
	mapper mappers.OrganizationMapper,
) *GormOrganizationRepository {
	return &GormOrganizationRepository{
		db:     db,
		mapper: mapper,
	}
}

func (r *GormOrganizationRepository) Save(org *entities.Organization) error {
	model := r.mapper.ToModel(org)
	return r.db.Save(model).Error
}

func (r *GormOrganizationRepository) GetByID(
	id valueobjects.OrganizationID,
) (*entities.Organization, error) {

	var model models.Organization
	err := r.db.
		Where("id = ?", id.Value.String()).
		First(&model).Error

	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return r.mapper.ToDomain(&model)
}

func (r *GormOrganizationRepository) GetByOwner(
	ownerID valueobjects.UserID,
) ([]*entities.Organization, error) {

	var modelsList []models.Organization
	err := r.db.
		Where("owner_user_id = ?", ownerID.Value.String()).
		Find(&modelsList).Error

	if err != nil {
		return nil, err
	}

	orgs := make([]*entities.Organization, 0, len(modelsList))
	for _, m := range modelsList {
		org, err := r.mapper.ToDomain(&m)
		if err != nil {
			return nil, err
		}
		orgs = append(orgs, org)
	}

	return orgs, nil
}
