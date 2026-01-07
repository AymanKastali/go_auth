package repositories

import (
	"errors"

	"go_auth/internal/adapters/mappers"
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/ports/repositories"
	"go_auth/internal/core/domain/aggregates"
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

func (r *GormUserRepository) Save(u *aggregates.User) error {
	model, err := r.mapper.ToModel(u)
	if err != nil {
		return apperr.NewInternalErr("mapping failed")
	}

	err = r.db.Omit("Roles.*").Create(model).Error
	return r.handleError(err, u.Email().String())
}

func (r *GormUserRepository) GetByEmail(email valueobjects.Email) (*aggregates.User, error) {
	var model models.User
	err := r.db.Preload("Roles").Where("email = ?", email.Value()).First(&model).Error

	if err != nil {
		// Return nil, nil if not found (standard Go repository pattern)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, r.handleError(err, email.Value())
	}

	return r.mapper.ToDomain(&model)
}

func (r *GormUserRepository) Update(u *aggregates.User) error {
	model, err := r.mapper.ToModel(u)
	if err != nil {
		return apperr.NewInternalErr("mapping failed")
	}

	err = r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Omit("Roles").Save(model).Error; err != nil {
			return err
		}
		return tx.Model(model).Association("Roles").Replace(model.Roles)
	})

	// Map the transaction error (e.g. unique constraint or connection loss)
	return r.handleError(err, u.ID().String())
}
func (r *GormUserRepository) GetByID(id valueobjects.UserID) (*aggregates.User, error) {
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

func (r *GormUserRepository) handleError(err error, id string) error {
	if err == nil {
		return nil
	}

	// GORM translates "23505" into gorm.ErrDuplicatedKey automatically
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return apperr.NewAlreadyExistsErr("user", id)
	}

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return apperr.NewNotFoundErr("user", id)
	}

	// Fallback for everything else
	return apperr.NewInternalErr(err.Error())
}
