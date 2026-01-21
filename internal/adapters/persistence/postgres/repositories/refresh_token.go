package repositories

import (
	"errors"
	"go_auth/internal/adapters/persistence/postgres/mappers"
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"

	"gorm.io/gorm"
)

type gormRefreshTokenRepository struct {
	db     *gorm.DB
	mapper *mappers.RefreshTokenMapper
	hasher ports.ITokenHasherService
}

func NewGormRefreshTokenRepository(
	db *gorm.DB,
	mapper *mappers.RefreshTokenMapper,
	hasher ports.ITokenHasherService,
) *gormRefreshTokenRepository {
	return &gormRefreshTokenRepository{
		db:     db,
		mapper: mapper,
		hasher: hasher,
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

func (r *gormRefreshTokenRepository) FindByRawToken(raw valueobjects.RawRefreshToken) (*entities.RefreshToken, error) {
	// 1. We MUST hash the raw token to find it in the DB
	// because we never store tokens in plain text.
	hashedTokenVO, err := r.hasher.Hash(raw.Value())
	if err != nil {
		return nil, err
	}

	var model models.RefreshToken
	err = r.db.Where("hash = ?", hashedTokenVO.Value()).First(&model).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}

	// 2. Map the DB model back to the Domain Entity
	return r.mapper.ToDomain(&model), nil
}

// FindByID returns the entity by ID or nil if not found
func (r *gormRefreshTokenRepository) FindByID(id valueobjects.TokenID) (*entities.RefreshToken, error) {
	if id.IsEmpty() {
		return nil, errors.New("id cannot be empty")
	}

	var model models.RefreshToken
	err := r.db.Where("id = ?", id.Value()).First(&model).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}

	return r.mapper.ToDomain(&model), nil
}

// FindByDevice returns all tokens for a given user and device
func (r *gormRefreshTokenRepository) FindByUserAndDevice(userID valueobjects.UserID, deviceID valueobjects.DeviceID) ([]*entities.RefreshToken, error) {
	if userID.IsEmpty() || deviceID.IsEmpty() {
		return nil, errors.New("userID and deviceID cannot be empty")
	}

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
	if userID.IsEmpty() {
		return nil, errors.New("userID cannot be empty")
	}

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
