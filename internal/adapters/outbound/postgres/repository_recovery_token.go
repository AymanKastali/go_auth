package postgres

import (
	"context"
	"errors"
	"go_auth/internal/domain"

	"gorm.io/gorm"
)

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
