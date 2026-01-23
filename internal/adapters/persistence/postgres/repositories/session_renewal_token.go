package repositories

import (
	"errors"
	"go_auth/internal/adapters/persistence/postgres/mappers"
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/valueobjects"

	"gorm.io/gorm"
)

type gormSessionRenewalTokenRepository struct {
	db     *gorm.DB
	mapper *mappers.SessionRenewalTokenMapper
}

func NewGormSessionRenewalTokenRepository(
	db *gorm.DB,
	mapper *mappers.SessionRenewalTokenMapper,
) *gormSessionRenewalTokenRepository {
	return &gormSessionRenewalTokenRepository{
		db:     db,
		mapper: mapper,
	}
}

// Save inserts or updates the entity
func (r *gormSessionRenewalTokenRepository) Save(e *entities.SessionRenewalToken) error {
	if e == nil {
		return errors.New("cannot save nil SessionRenewalToken")
	}

	model := r.mapper.ToModel(e)
	return r.db.Save(model).Error
}

func (r *gormSessionRenewalTokenRepository) SaveMany(tokens []*entities.SessionRenewalToken) error {
	if len(tokens) == 0 {
		return nil
	}

	dbModels := make([]*models.SessionRenewalToken, len(tokens))
	for i, e := range tokens {
		if e == nil {
			continue
		}
		dbModels[i] = r.mapper.ToModel(e)
	}

	// Using a transaction ensures that if one token fails to save,
	// the state doesn't end up partially updated.
	return r.db.Transaction(func(tx *gorm.DB) error {
		// tx.Save handles upserts automatically
		if err := tx.Save(&dbModels).Error; err != nil {
			return err
		}
		return nil
	})
}

// FindByID returns the entity by ID or nil if not found
func (r *gormSessionRenewalTokenRepository) FindByID(id valueobjects.SessionRenewalRawTokenID) (*entities.SessionRenewalToken, error) {
	var model models.SessionRenewalToken
	err := r.db.Where("id = ?", id.String()).First(&model).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return r.mapper.ToDomain(&model), nil
}

// FindByDevice returns all tokens for a given user and device
func (r *gormSessionRenewalTokenRepository) FindByUserAndDevice(userID valueobjects.UserID, deviceID valueobjects.DeviceID) ([]*entities.SessionRenewalToken, error) {
	var modelsList []models.SessionRenewalToken
	if err := r.db.Where("user_id = ? AND device_id = ?", userID.String(), deviceID.String()).Find(&modelsList).Error; err != nil {
		return nil, err
	}

	tokens := make([]*entities.SessionRenewalToken, len(modelsList))
	for i, m := range modelsList {
		tokens[i] = r.mapper.ToDomain(&m)
	}

	return tokens, nil
}

// FindByUser returns all tokens for a given user
func (r *gormSessionRenewalTokenRepository) FindByUser(userID valueobjects.UserID) ([]*entities.SessionRenewalToken, error) {
	var modelsList []models.SessionRenewalToken
	if err := r.db.Where("user_id = ?", userID.String()).Find(&modelsList).Error; err != nil {
		return nil, err
	}

	tokens := make([]*entities.SessionRenewalToken, len(modelsList))
	for i, m := range modelsList {
		tokens[i] = r.mapper.ToDomain(&m)
	}

	return tokens, nil
}
