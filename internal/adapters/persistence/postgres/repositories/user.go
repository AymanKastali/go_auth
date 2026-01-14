package repositories

import (
	"errors"
	"fmt"

	"go_auth/internal/adapters/persistence/postgres/mappers"
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/adapters/persistence/postgres/pgerr"
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"

	"gorm.io/gorm"
)

type GormUserRepository struct {
	db     *gorm.DB
	mapper mappers.IUserMapper
}

var _ ports.UserRepositoryPort = (*GormUserRepository)(nil)

func NewGormUserRepository(db *gorm.DB, mapper mappers.IUserMapper) ports.UserRepositoryPort {
	return &GormUserRepository{
		db:     db,
		mapper: mapper,
	}
}

func (r *GormUserRepository) Create(u *aggregates.User) error {
	model, err := r.mapper.ToModel(u)
	if err != nil {
		return err
	}

	return r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Omit("Roles.*").Create(model).Error; err != nil {
			if errors.Is(err, gorm.ErrDuplicatedKey) {
				return pgerr.WrapAlreadyExists(err, "user email or id already exists")
			}
			return pgerr.WrapUnavailable(err, "database failure during user creation")
		}
		return nil
	})
}

func (r *GormUserRepository) GetByEmail(email valueobjects.Email) (*aggregates.User, error) {
	var model models.User
	err := r.db.Preload("Roles").Where("email = ?", email.Value()).First(&model).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil // Return nil for not found as per use case logic
		}
		// Wrap database-level failures
		return nil, pgerr.WrapUnavailable(err, "failed to fetch user by email")
	}

	return r.mapper.ToDomain(&model)
}

func (r *GormUserRepository) GetByID(id valueobjects.UserID) (*aggregates.User, error) {
	var model models.User
	err := r.db.Preload("Roles").Where("id = ?", id.Value()).First(&model).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, pgerr.WrapUnavailable(err, "failed to fetch user by id")
	}

	return r.mapper.ToDomain(&model)
}

func (r *GormUserRepository) Update(u *aggregates.User) error {
	model, err := r.mapper.ToModel(u)
	if err != nil {
		return err
	}

	return r.db.Transaction(func(tx *gorm.DB) error {
		// 1. Update basic fields
		result := tx.Model(model).Omit("Roles").Select("*").Updates(model)
		if err := result.Error; err != nil {
			if errors.Is(err, gorm.ErrDuplicatedKey) {
				return pgerr.WrapAlreadyExists(err, "email already in use")
			}
			return pgerr.WrapUnavailable(err, "database failure during user update")
		}

		// Check if record actually existed
		if result.RowsAffected == 0 {
			return pgerr.WrapNotFound(fmt.Errorf("user with id %s not found", u.ID().Value()), "update failed")
		}

		// 2. Sync pivot table
		if err := tx.Model(model).Association("Roles").Replace(model.Roles); err != nil {
			return pgerr.WrapUnavailable(err, "failed to sync user roles")
		}

		return nil
	})
}
