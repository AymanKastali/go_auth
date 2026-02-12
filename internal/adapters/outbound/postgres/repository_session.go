package postgres

import (
	"context"
	"errors"
	"go_auth/internal/domain"

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
		Where("ulid = ?", id.String()).
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
		Where("user_ulid = ? AND is_revoked = ? AND fingerprint = ?", userID.String(), false, fp.String()).
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
		Where("user_ulid = ? AND is_revoked = ?", userID.String(), false).
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
	db := getDB(r.db, ctx)

	// Resolve own PK
	pk, err := resolvePK(db, &SessionModel{}, model.ULID)
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

func (r *postgresSessionRepository) RevokeAllForUser(ctx context.Context, userID domain.UserID, now domain.Timepoint) error {
	err := getDB(r.db, ctx).
		Model(&SessionModel{}).
		Where("user_ulid = ? AND is_revoked = ?", userID.String(), false).
		Updates(map[string]any{
			"is_revoked":     true,
			"last_active_at": now.Time(),
		}).Error

	if err != nil {
		return domain.ErrInternal
	}
	return nil
}
