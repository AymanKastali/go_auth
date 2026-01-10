package repositories

import (
	"errors"
	"go_auth/internal/adapters/persistence/postgres/mappers"
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/core/application/apperr"
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
		return apperr.NewInternalErr("role mapping failed")
	}

	// Use Create for new records; handleError will catch gorm.ErrDuplicatedKey
	err = r.db.Create(model).Error
	return r.handleError(err, role.Name())
}

func (r *GormRoleRepository) GetByID(id valueobjects.RoleID) (*aggregates.Role, error) {
	var model models.Role
	err := r.db.Where("id = ?", id.Value()).First(&model).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, r.handleError(err, id.Value())
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
		return nil, r.handleError(err, name)
	}

	return r.mapper.ToDomain(&model)
}

func (r *GormRoleRepository) GetAll() ([]*aggregates.Role, error) {
	var modelsList []models.Role
	if err := r.db.Find(&modelsList).Error; err != nil {
		return nil, r.handleError(err, "all_roles")
	}

	roles := make([]*aggregates.Role, len(modelsList))
	for i, m := range modelsList {
		role, err := r.mapper.ToDomain(&m)
		if err != nil {
			return nil, apperr.NewInternalErr("failed to map role from database")
		}
		roles[i] = role
	}

	return roles, nil
}

// Private helper to keep error handling consistent with UserRepository
func (r *GormRoleRepository) handleError(err error, id string) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return apperr.NewAlreadyExistsErr("role", id)
	}

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return apperr.NewNotFoundErr("role", id)
	}

	return apperr.NewInternalErr(err.Error())
}
