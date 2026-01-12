package repositories

import (
	"errors"

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
	if u == nil {
		return errors.New("cannot save a nil user aggregate")
	}

	model, err := r.mapper.ToModel(u)
	if err != nil {
		return err
	}

	if model == nil {
		return errors.New("user model is nil after mapping")
	}

	err = r.db.Omit("Roles.*").Create(model).Error
	if err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return pgerr.ErrConflict
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
			return nil, nil
		}
		return nil, err // Actual DB connection/syntax error
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
