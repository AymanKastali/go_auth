package repositories

import (
	"errors"
	"fmt"

	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/adapters/persistence/postgres/pgerr"
	"go_auth/internal/core/application/ports"
	"go_auth/internal/core/domain/aggregates"
	domainports "go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"

	"gorm.io/gorm"
)

type GormUserRepository struct {
	db     *gorm.DB
	mapper ports.IUserMapper
	idSvc  domainports.IIDService
	pwdSvc domainports.IPasswordHasherService
}

func NewGormUserRepository(
	db *gorm.DB,
	mapper ports.IUserMapper,
	idSvc domainports.IIDService,
	pwdSvc domainports.IPasswordHasherService,
) *GormUserRepository {
	return &GormUserRepository{
		db:     db,
		mapper: mapper,
		idSvc:  idSvc,
		pwdSvc: pwdSvc,
	}
}

func (r *GormUserRepository) Create(a *aggregates.User) error {
	model := r.mapper.ToModel(a)

	return r.db.Transaction(func(tx *gorm.DB) error {
		// Omit("Roles.*") prevents GORM from trying to create/update the Role records themselves
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
			return nil, nil
		}
		return nil, pgerr.WrapUnavailable(err, "failed to fetch user by email")
	}

	// GATEKEEPER: Validate all integrity rules (ID, Password Hash, Email, Status)
	if err := model.Validate(r.idSvc, r.pwdSvc); err != nil {
		return nil, err // Returns pgerr.isIntegrity
	}

	return r.mapper.ToDomain(&model), nil
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

	// GATEKEEPER: Validate all integrity rules
	if err := model.Validate(r.idSvc, r.pwdSvc); err != nil {
		return nil, err
	}

	return r.mapper.ToDomain(&model), nil
}

func (r *GormUserRepository) Update(a *aggregates.User) error {
	model := r.mapper.ToModel(a)

	return r.db.Transaction(func(tx *gorm.DB) error {
		// 1. Update basic fields using Select("*") to ensure all fields are sent, Omit Roles to handle separately
		result := tx.Model(model).Omit("Roles").Select("*").Updates(model)
		if err := result.Error; err != nil {
			if errors.Is(err, gorm.ErrDuplicatedKey) {
				return pgerr.WrapAlreadyExists(err, "email already in use")
			}
			return pgerr.WrapUnavailable(err, "database failure during user update")
		}

		if result.RowsAffected == 0 {
			return pgerr.WrapNotFound(fmt.Errorf("user with id %s not found", a.ID().Value()), "update failed")
		}

		// 2. Sync pivot table (Many-to-Many)
		if err := tx.Model(model).Association("Roles").Replace(model.Roles); err != nil {
			return pgerr.WrapUnavailable(err, "failed to sync user roles")
		}

		return nil
	})
}
