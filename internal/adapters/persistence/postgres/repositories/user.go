package repositories

import (
	"errors"

	"go_auth/internal/adapters/persistence/postgres/mappers"
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/derr" // Pointing inward to Domain
	"go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"

	"gorm.io/gorm"
)

type GormUserRepository struct {
	db     *gorm.DB
	mapper mappers.IUserMapper
}

var _ ports.UserRepositoryPort = (*GormUserRepository)(nil)

func NewGormUserRepository(
	db *gorm.DB,
	mapper mappers.IUserMapper,
) ports.UserRepositoryPort {
	return &GormUserRepository{
		db:     db,
		mapper: mapper,
	}
}

func (r *GormUserRepository) Save(u *aggregates.User) error {
	model, err := r.mapper.ToModel(u)
	if err != nil {
		return err // Mapping failure is a technical infrastructure error
	}

	err = r.db.Omit("Roles.*").Create(model).Error
	if err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			// This is a business rule: Emails must be unique
			return derr.NewViolation.EmailAlreadyTaken()
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
			return nil, nil // Use Case decides if NotFound is an error
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
			return nil, nil
		}
		return nil, err
	}

	return r.mapper.ToDomain(&model)
}

func (r *GormUserRepository) Update(u *aggregates.User) error {
	model, err := r.mapper.ToModel(u)
	if err != nil {
		return err
	}

	err = r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Omit("Roles").Save(model).Error; err != nil {
			return err
		}
		return tx.Model(model).Association("Roles").Replace(model.Roles)
	})

	return err
}
