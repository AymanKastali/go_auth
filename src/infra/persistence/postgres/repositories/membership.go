package repositories

import (
	"go_auth/src/domain/entities"
	value_objects "go_auth/src/domain/value_objects"
	"go_auth/src/infra/mappers"
	"go_auth/src/infra/persistence/postgres/models"

	"gorm.io/gorm"
)

type GormMembershipRepository struct {
	db     *gorm.DB
	mapper mappers.MembershipMapper
}

func NewGormMembershipRepository(
	db *gorm.DB,
	mapper mappers.MembershipMapper,
) *GormMembershipRepository {
	return &GormMembershipRepository{
		db:     db,
		mapper: mapper,
	}
}

func (r *GormMembershipRepository) Save(m *entities.Membership) error {
	model := r.mapper.ToModel(m)
	return r.db.Save(model).Error
}

func (r *GormMembershipRepository) GetByID(
	id value_objects.MembershipID,
) (*entities.Membership, error) {

	var model models.Membership
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

func (r *GormMembershipRepository) GetByUserAndOrganization(
	userID value_objects.UserID,
	orgID value_objects.OrganizationID,
) (*entities.Membership, error) {

	var model models.Membership
	err := r.db.
		Where("user_id = ? AND organization_id = ?",
			userID.Value.String(),
			orgID.Value.String(),
		).
		First(&model).Error

	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return r.mapper.ToDomain(&model)
}

func (r *GormMembershipRepository) GetByOrganization(
	orgID value_objects.OrganizationID,
) ([]*entities.Membership, error) {

	var modelsList []models.Membership
	err := r.db.
		Where("organization_id = ?", orgID.Value.String()).
		Find(&modelsList).Error

	if err != nil {
		return nil, err
	}

	result := make([]*entities.Membership, 0, len(modelsList))
	for _, m := range modelsList {
		d, err := r.mapper.ToDomain(&m)
		if err != nil {
			return nil, err
		}
		result = append(result, d)
	}

	return result, nil
}
