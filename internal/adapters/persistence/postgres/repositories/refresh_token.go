package repositories

import (
	"errors"
	"go_auth/internal/adapters/persistence/postgres/mappers"
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/valueobjects"

	"gorm.io/gorm"
)

type gormRefreshTokenRepository struct {
	db     *gorm.DB
	mapper *mappers.RefreshTokenMapper
}

func NewGormRefreshTokenRepository(
	db *gorm.DB,
	mapper *mappers.RefreshTokenMapper,
) *gormRefreshTokenRepository {
	return &gormRefreshTokenRepository{
		db:     db,
		mapper: mapper,
	}
}

// Save inserts or updates the entity
func (r *gormRefreshTokenRepository) Save(e *entities.RefreshToken) error {
	if e == nil {
		return errors.New("cannot save nil RefreshToken")
	}

	model := r.mapper.ToModel(e)
	return r.db.Save(model).Error
}

// FindByID returns the entity by ID or nil if not found
func (r *gormRefreshTokenRepository) FindByID(id valueobjects.TokenID) (*entities.RefreshToken, error) {
	var model models.RefreshToken
	err := r.db.Where("id = ?", id.Value()).First(&model).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return r.mapper.ToDomain(&model), nil
}

// FindByDevice returns all tokens for a given user and device
func (r *gormRefreshTokenRepository) FindByUserAndDevice(userID valueobjects.UserID, deviceID valueobjects.DeviceID) ([]*entities.RefreshToken, error) {
	var modelsList []models.RefreshToken
	if err := r.db.Where("user_id = ? AND device_id = ?", userID.Value(), deviceID.Value()).Find(&modelsList).Error; err != nil {
		return nil, err
	}

	tokens := make([]*entities.RefreshToken, len(modelsList))
	for i, m := range modelsList {
		tokens[i] = r.mapper.ToDomain(&m)
	}

	return tokens, nil
}

// FindByUser returns all tokens for a given user
func (r *gormRefreshTokenRepository) FindByUser(userID valueobjects.UserID) ([]*entities.RefreshToken, error) {
	var modelsList []models.RefreshToken
	if err := r.db.Where("user_id = ?", userID.Value()).Find(&modelsList).Error; err != nil {
		return nil, err
	}

	tokens := make([]*entities.RefreshToken, len(modelsList))
	for i, m := range modelsList {
		tokens[i] = r.mapper.ToDomain(&m)
	}

	return tokens, nil
}
