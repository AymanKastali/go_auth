package repositories

import (
	"errors"
	"go_auth/internal/adapters/persistence/postgres/mappers"
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/valueobjects"

	"gorm.io/gorm"
)

type gormRenewalTokenRepository struct {
	db     *gorm.DB
	mapper *mappers.RenewalTokenMapper
}

func NewGormRenewalTokenRepository(db *gorm.DB, mapper *mappers.RenewalTokenMapper) *gormRenewalTokenRepository {
	return &gormRenewalTokenRepository{
		db:     db,
		mapper: mapper,
	}
}

// Save inserts or updates the entity
func (r *gormRenewalTokenRepository) Save(e *entities.RenewalToken) error {
	if e == nil {
		return errors.New("cannot save nil RenewalToken")
	}

	model := r.mapper.ToModel(e)
	return r.db.Save(model).Error
}

// FindByHash returns the entity by hash or nil if not found
func (r *gormRenewalTokenRepository) FindByHash(hash valueobjects.HashedToken) (*entities.RenewalToken, error) {
	if hash.IsEmpty() {
		return nil, errors.New("hash cannot be empty")
	}

	var model models.RenewalToken
	err := r.db.Where("hash = ?", hash.Value()).First(&model).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}

	return r.mapper.ToDomain(&model), nil
}

// FindByID returns the entity by ID or nil if not found
func (r *gormRenewalTokenRepository) FindByID(id valueobjects.TokenID) (*entities.RenewalToken, error) {
	if id.IsEmpty() {
		return nil, errors.New("id cannot be empty")
	}

	var model models.RenewalToken
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
func (r *gormRenewalTokenRepository) FindByUserAndDevice(userID valueobjects.UserID, deviceID valueobjects.DeviceID) ([]*entities.RenewalToken, error) {
	if userID.IsEmpty() || deviceID.IsEmpty() {
		return nil, errors.New("userID and deviceID cannot be empty")
	}

	var modelsList []models.RenewalToken
	if err := r.db.Where("user_id = ? AND device_id = ?", userID.Value(), deviceID.Value()).Find(&modelsList).Error; err != nil {
		return nil, err
	}

	tokens := make([]*entities.RenewalToken, len(modelsList))
	for i, m := range modelsList {
		tokens[i] = r.mapper.ToDomain(&m)
	}

	return tokens, nil
}

// FindByUser returns all tokens for a given user
func (r *gormRenewalTokenRepository) FindByUser(userID valueobjects.UserID) ([]*entities.RenewalToken, error) {
	if userID.IsEmpty() {
		return nil, errors.New("userID cannot be empty")
	}

	var modelsList []models.RenewalToken
	if err := r.db.Where("user_id = ?", userID.Value()).Find(&modelsList).Error; err != nil {
		return nil, err
	}

	tokens := make([]*entities.RenewalToken, len(modelsList))
	for i, m := range modelsList {
		tokens[i] = r.mapper.ToDomain(&m)
	}

	return tokens, nil
}
