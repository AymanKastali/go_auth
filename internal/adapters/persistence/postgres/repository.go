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

	err := r.db.WithContext(ctx).
		Session(&gorm.Session{FullSaveAssociations: true}).
		Save(&model).Error

	if err != nil {
		// Map DB failure to Domain Sentinel
		return domain.ErrInternal
	}

	return nil
}

func (r *postgresUserRepository) FindByEmail(ctx context.Context, email domain.Email) (*domain.User, error) {
	var model UserModel

	err := r.db.WithContext(ctx).
		Preload("Sessions").
		Where("email = ?", email.String()).
		First(&model).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// In Hexagonal, returning (nil, nil) for "not found" is
			// the cleanest way for a Repo to say "nothing exists".
			return nil, nil
		}
		return nil, domain.ErrInternal
	}

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
		return nil, domain.ErrInternal
	}

	return toUserDomain(model)
}

func (r *postgresUserRepository) Delete(ctx context.Context, id domain.UserID) error {
	err := r.db.WithContext(ctx).
		Unscoped().
		Where("id = ?", id.String()).
		Delete(&UserModel{}).Error

	if err != nil {
		return domain.ErrInternal
	}
	return nil
}

func (r *postgresUserRepository) FindBySessionToken(ctx context.Context, token domain.HashedToken) (*domain.User, error) {
	var sessionModel SessionModel

	err := r.db.WithContext(ctx).
		Where("hashed_token = ?", token.String()).
		Where("revoked_at IS NULL").
		First(&sessionModel).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, domain.ErrInternal
	}

	// Border Control: Ensure data coming out of DB satisfies Domain VOs
	uid, err := domain.NewUserID(sessionModel.UserID)
	if err != nil {
		// If DB data violates our own ID rules, the system is in a corrupt state
		return nil, domain.ErrInternal
	}

	return r.FindByID(ctx, uid)
}
