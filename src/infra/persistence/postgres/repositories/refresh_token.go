package repositories

import (
	"go_auth/src/application/ports/repositories"
	"go_auth/src/infra/mappers"
	"go_auth/src/infra/persistence/postgres/models"
	"time"

	"gorm.io/gorm"
)

type GormRefreshTokenRepository struct {
	db     *gorm.DB
	mapper mappers.UserMapper
}

var _ repositories.RefreshTokenRepositoryPort = (*GormRefreshTokenRepository)(nil)

func NewGormRefreshTokenRepository(db *gorm.DB) *GormRefreshTokenRepository {
	return &GormRefreshTokenRepository{
		db: db,
	}
}

func (r *GormRefreshTokenRepository) Save(jti string, userID string, token string, expiresAt time.Time) error {
	rt := models.RefreshToken{
		ID:        jti,
		UserID:    userID,
		Token:     token,
		ExpiresAt: expiresAt,
	}
	return r.db.Create(&rt).Error
}

// Revoke marks a token as revoked
func (r *GormRefreshTokenRepository) Revoke(jti string) error {
	return r.db.Model(&models.RefreshToken{}).
		Where("id = ?", jti).
		Update("revoked_at", time.Now()).Error
}

// IsRevoked checks if a token has been revoked or expired
func (r *GormRefreshTokenRepository) IsRevoked(jti string) (bool, error) {
	var rt models.RefreshToken
	err := r.db.First(&rt, "id = ?", jti).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return true, nil // treat missing token as revoked
		}
		return false, err
	}

	if rt.RevokedAt != nil || time.Now().After(rt.ExpiresAt) {
		return true, nil
	}

	return false, nil
}
