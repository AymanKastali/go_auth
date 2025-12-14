package repositories

import (
	"go_auth/src/domain/entities"
	"go_auth/src/domain/ports/repositories"
	"go_auth/src/infra/mappers"

	"gorm.io/gorm"
)

type GormRoleRepository struct {
	DB     *gorm.DB
	Mapper mappers.RoleMapper
}

// Check that GormRoleRepository correctly implements the domain port contract
var _ repositories.RoleRepositoryPort = (*GormRoleRepository)(nil)

func NewGormRoleRepository(
	db *gorm.DB,
	mapper mappers.RoleMapper,
) repositories.RoleRepositoryPort {
	return &GormRoleRepository{
		DB:     db,
		Mapper: mapper,
	}
}

func (r *GormRoleRepository) Save(role *entities.Role) error {
	roleModel, err := r.Mapper.ToModel(role)
	if err != nil {
		return err
	}

	result := r.DB.Session(&gorm.Session{FullSaveAssociations: true}).Save(roleModel)

	if result.Error != nil {
		return result.Error
	}
	return nil
}
