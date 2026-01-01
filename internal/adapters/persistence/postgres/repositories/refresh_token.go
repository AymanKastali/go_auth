package repositories

import (
	"fmt"
	"go_auth/internal/adapters/mappers"
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/valueobjects"
	"time"

	"gorm.io/gorm"
)

type GormRefreshTokenRepository struct {
	db     *gorm.DB
	mapper *mappers.RefreshTokenMapper
}

// Constructor
func NewGormRefreshTokenRepository(db *gorm.DB, mapper *mappers.RefreshTokenMapper) *GormRefreshTokenRepository {
	return &GormRefreshTokenRepository{
		db:     db,
		mapper: mapper,
	}
}

// Save creates or updates a refresh token
func (r *GormRefreshTokenRepository) Save(token *entities.RefreshToken) error {
	model := r.mapper.ToModel(token)

	if err := r.db.Save(model).Error; err != nil {
		return fmt.Errorf("refresh token repository: failed to save token: %w", err)
	}

	return nil
}

// GetByID fetches a refresh token by its ID
func (r *GormRefreshTokenRepository) GetByID(tokenID valueobjects.TokenID) (*entities.RefreshToken, error) {
	var model models.RefreshToken
	if err := r.db.Where("id = ?", tokenID.String()).First(&model).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("refresh token repository: failed to get token by ID: %w", err)
	}

	return r.mapper.ToDomain(&model)
}

// GetByToken fetches a refresh token by its string value
func (r *GormRefreshTokenRepository) GetByToken(tokenStr string) (*entities.RefreshToken, error) {
	var model models.RefreshToken
	if err := r.db.Where("token = ?", tokenStr).First(&model).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("refresh token repository: failed to get token by value: %w", err)
	}

	return r.mapper.ToDomain(&model)
}

// Revoke marks a refresh token as revoked
func (r *GormRefreshTokenRepository) Revoke(tokenID valueobjects.TokenID, revokedAt time.Time) error {
	if err := r.db.Model(&models.RefreshToken{}).
		Where("id = ?", tokenID.String()).
		Update("revoked_at", revokedAt).Error; err != nil {
		return fmt.Errorf("refresh token repository: failed to revoke token: %w", err)
	}

	return nil
}

// GetByUserID retrieves all refresh tokens for a user
func (r *GormRefreshTokenRepository) GetByUserID(userID valueobjects.UserID) ([]*entities.RefreshToken, error) {
	var modelsList []models.RefreshToken
	if err := r.db.Where("user_id = ?", userID.String()).Find(&modelsList).Error; err != nil {
		return nil, fmt.Errorf("refresh token repository: failed to get tokens by user ID: %w", err)
	}

	tokens := make([]*entities.RefreshToken, len(modelsList))
	for i := range modelsList {
		t, err := r.mapper.ToDomain(&modelsList[i])
		if err != nil {
			return nil, fmt.Errorf("refresh token repository: failed to map token: %w", err)
		}
		tokens[i] = t
	}

	return tokens, nil
}

func (r *GormRefreshTokenRepository) IsRevoked(
	tokenID valueobjects.TokenID,
) (bool, error) {

	var token models.RefreshToken
	err := r.db.First(&token, "id = ?", tokenID.String()).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
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
	// We target records matching both IDs where revoked_at is still NULL
	result := r.db.Model(&models.RefreshToken{}).
		Where("user_id = ? AND device_id = ? AND revoked_at IS NULL",
			userID.String(),
			deviceID.String(),
		).
		Update("revoked_at", revokedAt)

	if result.Error != nil {
		return fmt.Errorf("refresh token repository: failed to revoke tokens by device: %w", result.Error)
	}

	return nil
}
