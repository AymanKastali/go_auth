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

type GormUserRepository struct {
	db     *gorm.DB
	mapper *mappers.UserMapper
}

var _ repositories.UserRepositoryPort = (*GormUserRepository)(nil)

func NewGormUserRepository(
	db *gorm.DB,
	mapper *mappers.UserMapper,
) repositories.UserRepositoryPort {
	return &GormUserRepository{
		db:     db,
		mapper: mapper,
	}
}

func (r *GormUserRepository) Save(u *entities.User) error {
	model, err := r.mapper.ToModel(u)
	if err != nil {
		return err
	}

	// Omit("Roles.*") tells GORM:
	// "Update the join table (user_roles), but don't touch the columns in the roles table."
	return r.db.Omit("Roles.*").Create(model).Error
}

func (r *GormUserRepository) GetByEmail(email valueobjects.Email) (*entities.User, error) {
	var model models.User
	err := r.db.Preload("Roles").Where("email = ?", email.Value()).First(&model).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return r.mapper.ToDomain(&model)
}

func (r *GormUserRepository) GetByID(id valueobjects.UserID) (*entities.User, error) {
	var model models.User
	err := r.db.Preload("Roles").Where("id = ?", id.String()).First(&model).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return r.mapper.ToDomain(&model)
}
func (r *GormUserRepository) Update(u *entities.User) error {
	model, err := r.mapper.ToModel(u)
	if err != nil {
		return fmt.Errorf("repository update: mapping failed: %w", err)
	}

	// We use a transaction to ensure the User and their Associations are updated correctly
	return r.db.Transaction(func(tx *gorm.DB) error {
		// 1. Update User basic fields
		if err := tx.Omit("Roles").Save(model).Error; err != nil {
			return err
		}

		// 2. Replace the associations in the join table
		// This ensures the Many-to-Many link is updated without wiping Role names
		if err := tx.Model(model).Association("Roles").Replace(model.Roles); err != nil {
			return err
		}

		return nil
	})
}
