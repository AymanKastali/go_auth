package postgres

import (
	"context"
	"errors"
	"go_auth/internal/domain"

	"gorm.io/gorm"
)

type postgresRecoveryTokenRepository struct {
	db *gorm.DB
}

func NewPostgresRecoveryTokenRepository(db *gorm.DB) domain.IRecoveryTokenRepository {
	return &postgresRecoveryTokenRepository{db: db}
}

func (r *postgresRecoveryTokenRepository) Save(ctx context.Context, token *domain.RecoveryToken) error {
	model := toRecoveryTokenModel(token)
	db := getDB(r.db, ctx)

	// Resolve own PK
	pk, err := resolvePK(db, &RecoveryTokenModel{}, model.ULID)
	if err != nil {
		return err
	}
	model.ID = pk

	// Resolve cross-aggregate FK: User
	userPK, err := resolveUserPK(db, model.UserULID)
	if err != nil {
		return err
	}
	model.UserID = userPK

	if err := db.Save(&model).Error; err != nil {
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

	return toRecoveryTokenDomain(model), nil
}

func (r *postgresRecoveryTokenRepository) RevokeAllForUser(ctx context.Context, uid domain.UserID) error {
	err := getDB(r.db, ctx).
		Model(&RecoveryTokenModel{}).
		Where("user_ulid = ? AND is_used = false", uid.String()).
		Update("is_used", true).Error

	if err != nil {
		return domain.ErrInternal
	}
	return nil
}
