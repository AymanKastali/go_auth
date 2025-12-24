package repositories

import (
	"fmt"
	"go_auth/src/domain/entities"
	"go_auth/src/domain/value_objects"
	"go_auth/src/infra/mappers"
	"go_auth/src/infra/persistence/postgres/models"
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
func (r *GormRefreshTokenRepository) GetByID(tokenID value_objects.TokenId) (*entities.RefreshToken, error) {
	var model models.RefreshToken
	if err := r.db.Where("id = ?", tokenID.Value.String()).First(&model).Error; err != nil {
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
func (r *GormRefreshTokenRepository) Revoke(tokenID value_objects.TokenId, revokedAt time.Time) error {
	if err := r.db.Model(&models.RefreshToken{}).
		Where("id = ?", tokenID.Value.String()).
		Update("revoked_at", revokedAt).Error; err != nil {
		return fmt.Errorf("refresh token repository: failed to revoke token: %w", err)
	}

	return nil
}

// GetByUserID retrieves all refresh tokens for a user
func (r *GormRefreshTokenRepository) GetByUserID(userID value_objects.UserId) ([]*entities.RefreshToken, error) {
	var modelsList []models.RefreshToken
	if err := r.db.Where("user_id = ?", userID.Value.String()).Find(&modelsList).Error; err != nil {
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

func (r *GormRefreshTokenRepository) IsRevoked(tokenID value_objects.TokenId) (bool, error) {
	var token models.RefreshToken
	if err := r.db.First(&token, "id = ?", tokenID.Value.String()).Error; err != nil {
		return false, err
	}
	return token.RevokedAt != nil, nil
}
