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
	if token == nil {
		return derr.ErrRequired("refresh token")
	}

	model := r.mapper.ToModel(token)
	err := r.db.Save(model).Error
	if err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			// Maps to CodeConflict
			return derr.ErrDuplicate("token", token.ID().Value())
		}
		return err
	}
	return nil
}

func (r *GormRefreshTokenRepository) GetByID(tokenID valueobjects.TokenID) (*entities.RefreshToken, error) {
	var model models.RefreshToken
	err := r.db.Where("id = ?", tokenID.Value()).First(&model).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil // Handled by Use Case logic
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
		Where("id = ? AND revoked_at IS NULL", tokenID.Value()).
		Update("revoked_at", revokedAt)

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		// If we tried to revoke something that doesn't exist or is already revoked
		return derr.ErrNotFound("Active refresh token", tokenID.Value())
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
			return nil, err
		}
		tokens[i] = t
	}
	return tokens, nil
}

func (r *GormRefreshTokenRepository) IsRevoked(tokenID valueobjects.TokenID) (bool, error) {
	var token models.RefreshToken
	// We only need the one column
	err := r.db.Select("revoked_at").First(&token, "id = ?", tokenID.Value()).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// If the record isn't there, it's effectively "revoked" or invalid
			return true, nil
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
	// Standard infrastructure error return.
	// If 0 rows are updated, it just means there was no active session to clear, which isn't a domain error here.
	return r.db.Model(&models.RefreshToken{}).
		Where("user_id = ? AND device_id = ? AND revoked_at IS NULL",
			userID.Value(),
			deviceID.Value(),
		).
		Update("revoked_at", revokedAt).Error
}
