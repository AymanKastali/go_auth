package postgres

import (
	"context"
	"errors"
	"go_auth/internal/core/domain"

	"gorm.io/gorm"
)

type postgresUserRepository struct {
	db *gorm.DB
}

func NewPostgresUserRepository(db *gorm.DB) domain.IUserRepository {
	return &postgresUserRepository{db: db}
}

func (r *postgresUserRepository) Save(ctx context.Context, user *domain.User) error {
	model := toUserModel(user)
	db := getDB(r.db, ctx)

	// Save the user record itself (omit associations to avoid FK ordering issues)
	if err := db.Omit("UserRoles").Save(&model).Error; err != nil {
		return domain.ErrInternal
	}

	// Replace user_roles: delete existing, insert current
	if err := db.Where("user_id = ?", model.ID).Delete(&UserRoleModel{}).Error; err != nil {
		return domain.ErrInternal
	}
	if len(model.UserRoles) > 0 {
		if err := db.Create(&model.UserRoles).Error; err != nil {
			return domain.ErrInternal
		}
	}

	return nil
}

func (r *postgresUserRepository) FindByEmail(ctx context.Context, email domain.Email) (*domain.User, error) {
	var model UserModel
	err := getDB(r.db, ctx).
		Preload("UserRoles").
		Where("email = ?", email.String()).
		First(&model).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, domain.ErrInternal
	}
	return toUserDomain(model)
}

func (r *postgresUserRepository) FindByID(ctx context.Context, id domain.UserID) (*domain.User, error) {
	var model UserModel
	err := getDB(r.db, ctx).
		Preload("UserRoles").
		Where("id = ?", id.String()).
		First(&model).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, domain.ErrInternal
	}
	return toUserDomain(model)
}

func (r *postgresUserRepository) Delete(ctx context.Context, id domain.UserID) error {
	err := getDB(r.db, ctx).
		Unscoped().
		Where("id = ?", id.String()).
		Delete(&UserModel{}).Error

	if err != nil {
		return domain.ErrInternal
	}
	return nil
}
