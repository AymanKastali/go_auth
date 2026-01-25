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
	// 1. Map Domain Aggregate -> Persistence Model
	model := toUserModel(user)

	// 2. Execute Save (GORM handles Insert/Update automatically via Primary Key)
	// .Session(&gorm.Session{FullSaveAssociations: true}) ensures sessions are synced
	err := r.db.WithContext(ctx).
		Session(&gorm.Session{FullSaveAssociations: true}).
		Save(&model).Error

	if err != nil {
		// Handle unique constraint violations for Email
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return domain.NewEmailAlreadyTakenError(user.Email().String())
		}
		return domain.NewInternalError("failed to persist user aggregate", err)
	}

	return nil
}

func (r *postgresUserRepository) FindByEmail(ctx context.Context, email domain.Email) (*domain.User, error) {
	var model UserModel

	// .First() returns ErrRecordNotFound if no user exists
	err := r.db.WithContext(ctx).
		Preload("Sessions").
		Where("email = ?", email.String()).
		First(&model).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil // Not an error, just not found
		}
		return nil, domain.NewInternalError("database query failed during find-by-email", err)
	}

	// 3. Map back to Domain using our "Smart Mapper"
	return toUserDomain(model)
}

func (r *postgresUserRepository) FindByID(ctx context.Context, id domain.UserID) (*domain.User, error) {
	var model UserModel

	err := r.db.WithContext(ctx).
		Preload("Sessions").
		Where("id = ?", id.String()).
		First(&model).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, domain.NewInternalError("database query failed during find-by-id", err)
	}

	return toUserDomain(model)
}

func (r *postgresUserRepository) Delete(ctx context.Context, id domain.UserID) error {
	// We use Unscoped() to ensure GORM doesn't try to be "smart"
	// and do a soft delete if it sees a deleted_at column.
	err := r.db.WithContext(ctx).
		Unscoped().
		Where("id = ?", id.String()).
		Delete(&UserModel{}).Error

	if err != nil {
		return domain.NewInternalError("failed to physically delete user", err)
	}
	return nil
}
