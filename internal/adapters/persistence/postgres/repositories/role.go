package repositories

import (
	"errors"
	"fmt"

	"go_auth/internal/adapters/mappers"
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/core/application/ports/repositories"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/valueobjects"

	"gorm.io/gorm"
)

type GormRoleRepository struct {
	db     *gorm.DB
	mapper *mappers.RoleMapper
}

var _ repositories.RoleRepositoryPort = (*GormRoleRepository)(nil)

func NewGormRoleRepository(db *gorm.DB, mapper *mappers.RoleMapper) repositories.RoleRepositoryPort {
	return &GormRoleRepository{
		db:     db,
		mapper: mapper,
	}
}

func (r *GormRoleRepository) Save(role *entities.Role) error {
	model, err := r.mapper.ToModel(role)
	if err != nil {
		return fmt.Errorf("role repository: mapping failed: %w", err)
	}
	fmt.Printf("DEBUG: Saving Role - ID: %s, Name: '%s'\n", model.ID, model.Name)
	// return r.db.Save(model).Error
	return r.db.Create(model).Error
}

func (r *GormRoleRepository) GetByID(id valueobjects.RoleID) (*entities.Role, error) {
	var model models.Role
	err := r.db.Where("id = ?", id.String()).First(&model).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("role repository: fetch by ID failed: %w", err)
	}

	return r.mapper.ToDomain(&model)
}

func (r *GormRoleRepository) GetByName(name string) (*entities.Role, error) {
	var model models.Role
	err := r.db.Where("name = ?", name).First(&model).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("role repository: fetch by name failed: %w", err)
	}

	return r.mapper.ToDomain(&model)
}

func (r *GormRoleRepository) GetAll() ([]*entities.Role, error) {
	var modelsList []models.Role
	if err := r.db.Find(&modelsList).Error; err != nil {
		return nil, fmt.Errorf("role repository: fetch all failed: %w", err)
	}

	roles := make([]*entities.Role, len(modelsList))
	for i, m := range modelsList {
		role, _ := r.mapper.ToDomain(&m)
		roles[i] = role
	}

	return roles, nil
}
