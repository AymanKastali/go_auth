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

	// Using getDB to support TransactionManager
	err := getDB(r.db, ctx).
		Session(&gorm.Session{FullSaveAssociations: true}).
		Save(&model).Error

	if err != nil {
		return domain.ErrInternal
	}
	return nil
}
func (r *postgresUserRepository) FindByEmail(ctx context.Context, email domain.Email) (*domain.User, error) {
	var model UserModel
	err := getDB(r.db, ctx).
		Preload("Sessions").
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
	err := getDB(r.db, ctx).
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
	// We use getDB even for reads to ensure read-your-writes consistency in transactions
	err := getDB(r.db, ctx).
		Where("hashed_token = ?", token.String()).
		Where("revoked_at IS NULL").
		First(&sessionModel).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, domain.ErrInternal
	}

	uid, err := domain.NewUserID(sessionModel.UserID)
	if err != nil {
		return nil, domain.ErrInternal
	}

	return r.FindByID(ctx, uid)
}

// Revoked Tokens
type postgresRecoveryTokenRepository struct {
	db *gorm.DB
}

func NewPostgresRecoveryTokenRepository(db *gorm.DB) domain.IRecoveryTokenRepository {
	return &postgresRecoveryTokenRepository{db: db}
}

func (r *postgresRecoveryTokenRepository) Save(ctx context.Context, token *domain.RecoveryToken) error {
	// 1. Map to DB Model
	model := toRecoveryTokenModel(token)

	// 2. Execute SQL with Transaction Support
	err := getDB(r.db, ctx).Save(&model).Error
	if err != nil {
		return domain.ErrInternal
	}
	return nil
}

func (r *postgresRecoveryTokenRepository) FindByHash(ctx context.Context, hash domain.RecoveryTokenHash) (*domain.RecoveryToken, error) {
	var model RecoveryTokenModel

	err := getDB(r.db, ctx).
		Where("hashed_token = ?", hash.String()).
		First(&model).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, domain.ErrInternal
	}

	// 3. Map back to Domain Entity
	return toRecoveryTokenDomain(model), nil
}

func (r *postgresRecoveryTokenRepository) RevokeAllForUser(ctx context.Context, uid domain.UserID, now domain.Timepoint) error {
	t := now.Time()
	err := getDB(r.db, ctx).
		Model(&RecoveryTokenModel{}).
		Where("user_id = ? AND used_at IS NULL", uid.String()).
		Update("used_at", t).Error

	if err != nil {
		return domain.ErrInternal
	}
	return nil
}
