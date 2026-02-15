package postgres

import (
	"context"
	"errors"
	"go_auth/internal/domain"

	"gorm.io/gorm"
)

type postgresActivationTokenRepository struct {
	db *gorm.DB
}

func NewPostgresActivationTokenRepository(db *gorm.DB) domain.IActivationTokenRepository {
	return &postgresActivationTokenRepository{db: db}
}

func (r *postgresActivationTokenRepository) Save(ctx context.Context, token *domain.ActivationToken) error {
	model := toActivationTokenModel(token)
	db := getDB(r.db, ctx)

	// Resolve own PK
	pk, err := resolvePK(db, &ActivationTokenModel{}, model.ULID)
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

func (r *postgresActivationTokenRepository) FindByHash(ctx context.Context, hash domain.ActivationTokenHash) (*domain.ActivationToken, error) {
	var model ActivationTokenModel

	err := getDB(r.db, ctx).
		Where("hashed_token = ?", hash.String()).
		First(&model).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, domain.ErrInternal
	}

	return toActivationTokenDomain(model), nil
}

func (r *postgresActivationTokenRepository) RevokeAllForUser(ctx context.Context, uid domain.UserID) error {
	err := getDB(r.db, ctx).
		Model(&ActivationTokenModel{}).
		Where("user_ulid = ? AND is_used = false", uid.String()).
		Update("is_used", true).Error

	if err != nil {
		return domain.ErrInternal
	}
	return nil
}
