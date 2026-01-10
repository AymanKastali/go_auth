package repositories

import (
	"errors"

	"go_auth/internal/adapters/persistence/postgres/mappers"
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/adapters/persistence/postgres/pgerr"
	"go_auth/internal/core/application/apperr"
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
	model, err := r.mapper.ToModel(u)
	if err != nil {
		// Mapping TO model usually fails only on logic bugs; map it to Internal
		return apperr.NewInternalErr("failed to prepare user for persistence")
	}

	err = r.db.Omit("Roles.*").Create(model).Error
	return r.mapPGErr(err, u.Email().String())
}

func (r *GormUserRepository) GetByEmail(email valueobjects.Email) (*aggregates.User, error) {
	var model models.User
	err := r.db.Preload("Roles").Where("email = ?", email.Value()).First(&model).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, r.mapPGErr(err, email.Value())
	}

	domainUser, err := r.mapper.ToDomain(&model)
	if err != nil {
		// FIX: Map the pgerr.DataCorruptionErr to an apperr
		return nil, r.mapPGErr(err, email.Value())
	}

	return domainUser, nil
}

func (r *GormUserRepository) GetByID(id valueobjects.UserID) (*aggregates.User, error) {
	var model models.User
	err := r.db.Preload("Roles").Where("id = ?", id.Value()).First(&model).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, r.mapPGErr(err, id.Value())
	}

	domainUser, err := r.mapper.ToDomain(&model)
	if err != nil {
		// FIX: Map the pgerr.DataCorruptionErr to an apperr
		return nil, r.mapPGErr(err, id.Value())
	}

	return domainUser, nil
}

func (r *GormUserRepository) Update(u *aggregates.User) error {
	model, err := r.mapper.ToModel(u)
	if err != nil {
		return apperr.NewInternalErr("failed to prepare user for update")
	}

	err = r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Omit("Roles").Save(model).Error; err != nil {
			return err
		}
		return tx.Model(model).Association("Roles").Replace(model.Roles)
	})

	return r.mapPGErr(err, u.ID().Value())
}

func (r *GormUserRepository) mapPGErr(err error, id string) error {
	if err == nil {
		return nil
	}

	// 1. Handle Infrastructure Invariants (PostgresErr / PersistenceErr)
	// This catches the pgerr.DataCorruptionErr returned by your Mapper.
	var pgErr pgerr.PostgresErr
	if errors.As(err, &pgErr) {
		// log.Error("Critical data integrity issue", "err", pgErr.Error())
		return apperr.NewInternalErr("internal data integrity violation")
	}

	// 2. Handle Known GORM/Postgres Constraint Errors
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return apperr.NewAlreadyExistsErr("user", id)
	}

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return apperr.NewNotFoundErr("user", id)
	}

	// 3. Professional Fallback
	// We log the raw err.Error() internally, but NEVER return it to the App layer.
	// log.Error("Unexpected database failure", "err", err)
	return apperr.NewInternalErr("an unexpected error occurred while accessing the data store")
}
