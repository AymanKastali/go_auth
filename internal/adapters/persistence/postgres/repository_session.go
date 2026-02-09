package postgres

import (
	"context"
	"errors"
	"go_auth/internal/core/domain"

	"gorm.io/gorm"
)

type postgresSessionRepository struct {
	db *gorm.DB
}

func NewPostgresSessionRepository(db *gorm.DB) domain.ISessionRepository {
	return &postgresSessionRepository{db: db}
}

func (r *postgresSessionRepository) FindByID(ctx context.Context, id domain.SessionID) (*domain.Session, error) {
	var model SessionModel
	err := getDB(r.db, ctx).
		Where("id = ?", id.String()).
		First(&model).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, domain.ErrInternal
	}
	return toSessionDomain(model), nil
}

func (r *postgresSessionRepository) FindByToken(ctx context.Context, token domain.HashedToken) (*domain.Session, error) {
	var model SessionModel
	err := getDB(r.db, ctx).
		Where("hashed_token = ?", token.String()).
		First(&model).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, domain.ErrInternal
	}
	return toSessionDomain(model), nil
}

func (r *postgresSessionRepository) FindActiveByUserAndFingerprint(ctx context.Context, userID domain.UserID, fp domain.DeviceFingerprint) (*domain.Session, error) {
	var model SessionModel
	err := getDB(r.db, ctx).
		Where("user_id = ? AND is_revoked = ? AND fingerprint = ?", userID.String(), false, fp.String()).
		First(&model).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, domain.ErrInternal
	}
	return toSessionDomain(model), nil
}

func (r *postgresSessionRepository) FindActiveByUserID(ctx context.Context, userID domain.UserID) ([]*domain.Session, error) {
	var models []SessionModel
	err := getDB(r.db, ctx).
		Where("user_id = ? AND is_revoked = ?", userID.String(), false).
		Order("last_active_at ASC").
		Find(&models).Error

	if err != nil {
		return nil, domain.ErrInternal
	}

	sessions := make([]*domain.Session, len(models))
	for i, m := range models {
		sessions[i] = toSessionDomain(m)
	}
	return sessions, nil
}

func (r *postgresSessionRepository) Save(ctx context.Context, session *domain.Session) error {
	model := toSessionModel(session)

	err := getDB(r.db, ctx).Save(&model).Error
	if err != nil {
		return domain.ErrInternal
	}
	return nil
}

func (r *postgresSessionRepository) RevokeAllForUser(ctx context.Context, userID domain.UserID, now domain.Timepoint) error {
	err := getDB(r.db, ctx).
		Model(&SessionModel{}).
		Where("user_id = ? AND is_revoked = ?", userID.String(), false).
		Updates(map[string]interface{}{
			"is_revoked":     true,
			"last_active_at": now.Time(),
		}).Error

	if err != nil {
		return domain.ErrInternal
	}
	return nil
}
