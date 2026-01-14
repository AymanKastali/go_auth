package repositories

import (
	"errors"

	"go_auth/internal/adapters/persistence/postgres/mappers"
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/adapters/persistence/postgres/pgerr" // Use pgerr instead of derr
	"go_auth/internal/core/domain/aggregates"
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
	model, err := r.mapper.ToModel(role)
	if err != nil {
		return err
	}

	if err := r.db.Create(model).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			// Infrastructure returns WrapAlreadyExists, UseCase decides the Domain Error
			return pgerr.WrapAlreadyExists(err, "role name already exists")
		}
		return pgerr.WrapUnavailable(err, "failed to save role")
	}
	return nil
}

func (r *GormRoleRepository) GetByID(id valueobjects.RoleID) (*aggregates.Role, error) {
	var model models.Role
	err := r.db.Where("id = ?", id.Value()).First(&model).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil // Nil return for 404/Check logic in UseCase
		}
		return nil, pgerr.WrapUnavailable(err, "failed to fetch role by id")
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
		return nil, pgerr.WrapUnavailable(err, "failed to fetch role by name")
	}

	return r.mapper.ToDomain(&model)
}

func (r *GormRoleRepository) GetAll() ([]*aggregates.Role, error) {
	var modelsList []models.Role
	if err := r.db.Find(&modelsList).Error; err != nil {
		return nil, pgerr.WrapUnavailable(err, "failed to fetch all roles")
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
