package repositories

import (
	"errors"
	"go_auth/internal/adapters/persistence/postgres/mappers"
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/derr"
	"go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"

	"gorm.io/gorm"
)

type GormRoleRepository struct {
	db     *gorm.DB
	mapper mappers.IRoleMapper
}

var _ ports.RoleRepositoryPort = (*GormRoleRepository)(nil)

func NewGormRoleRepository(db *gorm.DB, mapper mappers.IRoleMapper) ports.RoleRepositoryPort {
	return &GormRoleRepository{
		db:     db,
		mapper: mapper,
	}
}

func (r *GormRoleRepository) Save(role *aggregates.Role) error {
	if role == nil {
		return derr.ErrRequired("role")
	}

	model, err := r.mapper.ToModel(role)
	if err != nil {
		return err
	}

	err = r.db.Create(model).Error
	if err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			// Mapping to domain CodeConflict
			return derr.ErrDuplicate("role name", role.Name())
		}
		return err
	}
	return nil
}

func (r *GormRoleRepository) GetByID(id valueobjects.RoleID) (*aggregates.Role, error) {
	var model models.Role
	// Using .First() which triggers ErrRecordNotFound if not present
	err := r.db.Where("id = ?", id.Value()).First(&model).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Returning nil, nil as per your request,
			// though returning derr.ErrNotFound is also a valid DDD choice.
			return nil, nil
		}
		return nil, err
	}

	return r.mapper.ToDomain(&model)
}

func (r *GormRoleRepository) GetByName(name string) (*aggregates.Role, error) {
	var model models.Role
	err := r.db.Where("name = ?", name).First(&model).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}

	return r.mapper.ToDomain(&model)
}

func (r *GormRoleRepository) GetAll() ([]*aggregates.Role, error) {
	var modelsList []models.Role
	// .Find() doesn't return ErrRecordNotFound for empty sets, just an empty slice
	if err := r.db.Find(&modelsList).Error; err != nil {
		return nil, err
	}

	roles := make([]*aggregates.Role, len(modelsList))
	for i, m := range modelsList {
		role, err := r.mapper.ToDomain(&m)
		if err != nil {
			return nil, err
		}
		roles[i] = role
	}

	return roles, nil
}
