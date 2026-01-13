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

func (r *GormUserRepository) Save(u *aggregates.User) error {
	if u == nil {
		return derr.ErrRequired("user aggregate")
	}

	model, err := r.mapper.ToModel(u)
	if err != nil {
		return err // Internal mapping error
	}

	err = r.db.Omit("Roles.*").Create(model).Error
	if err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			// Using your domain's duplicate error
			return derr.ErrDuplicate("email", u.Email().Value())
		}
		return err
	}
	return nil
}

func (r *GormUserRepository) GetByEmail(email valueobjects.Email) (*aggregates.User, error) {
	var model models.User
	err := r.db.Preload("Roles").Where("email = ?", email.Value()).First(&model).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// In many DDD patterns, GetByEmail might return nil/nil
			// OR a specific Domain NotFound error.
			// Since your UseCase expects a check for user == nil, we return nil/nil
			// but could also return derr.ErrNotFound("User", email.Value())
			return nil, nil
		}
		return nil, err
	}

	return r.mapper.ToDomain(&model)
}

func (r *GormUserRepository) GetByID(id valueobjects.UserID) (*aggregates.User, error) {
	var model models.User
	err := r.db.Preload("Roles").Where("id = ?", id.Value()).First(&model).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Explicitly returning the domain error for ID lookups
			return nil, derr.ErrNotFound("User", id.Value())
		}
		return nil, err
	}

	return r.mapper.ToDomain(&model)
}

func (r *GormUserRepository) Update(u *aggregates.User) error {
	if u == nil {
		return derr.ErrRequired("user aggregate")
	}

	model, err := r.mapper.ToModel(u)
	if err != nil {
		return err
	}

	err = r.db.Transaction(func(tx *gorm.DB) error {
		// Save will update based on primary key
		if err := tx.Omit("Roles").Save(model).Error; err != nil {
			if errors.Is(err, gorm.ErrDuplicatedKey) {
				return derr.ErrDuplicate("email", u.Email().Value())
			}
			return err
		}
		// Sync associations
		return tx.Model(model).Association("Roles").Replace(model.Roles)
	})

	return err
}
