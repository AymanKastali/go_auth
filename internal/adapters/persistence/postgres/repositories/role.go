package repositories

import (
	"errors"
	"strings"

	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/adapters/persistence/postgres/pgerr"
	"go_auth/internal/core/application/ports"
	"go_auth/internal/core/domain/aggregates"
	domainports "go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"

	"gorm.io/gorm"
)

type GormRoleRepository struct {
	db     *gorm.DB
	mapper ports.IRoleMapper
	idSvc  domainports.IIDService
}

func NewGormRoleRepository(
	db *gorm.DB,
	mapper ports.IRoleMapper,
	idSvc domainports.IIDService,
) *GormRoleRepository {
	return &GormRoleRepository{
		db:     db,
		mapper: mapper,
		idSvc:  idSvc,
	}
}

func (r *GormRoleRepository) Save(role *aggregates.Role) error {
	// Mapper is now dumb
	model := r.mapper.ToModel(role)

	if err := r.db.Save(model).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
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
			return nil, nil
		}
		return nil, pgerr.WrapUnavailable(err, "failed to fetch role by id")
	}

	// GATEKEEPER
	if err := model.Validate(r.idSvc); err != nil {
		return nil, err
	}

	return r.mapper.ToDomain(&model), nil
}

func (r *GormRoleRepository) GetByName(name string) (*aggregates.Role, error) {
	var model models.Role

	normalizedName := strings.ToLower(strings.TrimSpace(name))

	err := r.db.Where("LOWER(name) = ?", normalizedName).First(&model).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, pgerr.WrapUnavailable(err, "failed to fetch role by name")
	}

	if err := model.Validate(r.idSvc); err != nil {
		return nil, err
	}

	return r.mapper.ToDomain(&model), nil
}

func (r *GormRoleRepository) GetAll() ([]*aggregates.Role, error) {
	var modelsList []models.Role
	if err := r.db.Find(&modelsList).Error; err != nil {
		return nil, pgerr.WrapUnavailable(err, "failed to fetch all roles")
	}

	roles := make([]*aggregates.Role, len(modelsList))
	for i := range modelsList {
		// ALL OR NOTHING
		if err := modelsList[i].Validate(r.idSvc); err != nil {
			return nil, err
		}
		roles[i] = r.mapper.ToDomain(&modelsList[i])
	}

	return roles, nil
}
