package repositories

import (
	"errors"
	"go_auth/internal/adapters/persistence/postgres/mappers"
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/core/domain/derr"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/valueobjects"
	"time"

	"gorm.io/gorm"
)

type GormRefreshTokenRepository struct {
	db     *gorm.DB
	mapper mappers.IRefreshTokenMapper
}

func NewGormRefreshTokenRepository(
	db *gorm.DB,
	mapper mappers.IRefreshTokenMapper,
) *GormRefreshTokenRepository {
	return &GormRefreshTokenRepository{
		db:     db,
		mapper: mapper,
	}
}

func (r *GormRefreshTokenRepository) Save(token *entities.RefreshToken) error {
	model := r.mapper.ToModel(token)
	err := r.db.Save(model).Error
	if err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return derr.NewViolation.TokenAlreadyExists()
		}
		return err // Use Case will wrap in apperr.Internal
	}
	return nil
}

func (r *GormRefreshTokenRepository) GetByID(tokenID valueobjects.TokenID) (*entities.RefreshToken, error) {
	var model models.RefreshToken
	err := r.db.Where("id = ?", tokenID.Value()).First(&model).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil // Let Use Case handle the "NotFound" logic
		}
		return nil, err
	}
	return r.mapper.ToDomain(&model)
}

func (r *GormRefreshTokenRepository) GetByToken(tokenStr string) (*entities.RefreshToken, error) {
	var model models.RefreshToken
	err := r.db.Where("token = ?", tokenStr).First(&model).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return r.mapper.ToDomain(&model)
}

func (r *GormRefreshTokenRepository) Revoke(tokenID valueobjects.TokenID, revokedAt time.Time) error {
	result := r.db.Model(&models.RefreshToken{}).
		Where("id = ?", tokenID.Value()).
		Update("revoked_at", revokedAt)

	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return derr.NewViolation.TokenNotFound()
	}
	return nil
}

func (r *GormRefreshTokenRepository) GetByUserID(userID valueobjects.UserID) ([]*entities.RefreshToken, error) {
	var modelsList []models.RefreshToken
	err := r.db.Where("user_id = ?", userID.Value()).Find(&modelsList).Error
	if err != nil {
		return nil, err
	}

	tokens := make([]*entities.RefreshToken, len(modelsList))
	for i := range modelsList {
		t, err := r.mapper.ToDomain(&modelsList[i])
		if err != nil {
			return nil, err // Technical mapping failure
		}
		tokens[i] = t
	}
	return tokens, nil
}

func (r *GormRefreshTokenRepository) IsRevoked(tokenID valueobjects.TokenID) (bool, error) {
	var token models.RefreshToken
	err := r.db.Select("revoked_at").First(&token, "id = ?", tokenID.Value()).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return true, nil // If it doesn't exist, treat as revoked/invalid
		}
		return false, err
	}

	return token.RevokedAt != nil, nil
}

func (r *GormRefreshTokenRepository) RevokeByDeviceID(
	userID valueobjects.UserID,
	deviceID valueobjects.DeviceID,
	revokedAt time.Time,
) error {
	err := r.db.Model(&models.RefreshToken{}).
		Where("user_id = ? AND device_id = ? AND revoked_at IS NULL",
			userID.Value(),
			deviceID.Value(),
		).
		Update("revoked_at", revokedAt).Error

	return err
}
