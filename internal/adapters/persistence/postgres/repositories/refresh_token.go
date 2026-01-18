package repositories

import (
	"errors"

	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/adapters/persistence/postgres/pgerr"
	"go_auth/internal/core/application/ports"
	"go_auth/internal/core/domain/entities"
	domainports "go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"

	"gorm.io/gorm"
)

type GormRefreshTokenRepository struct {
	db     *gorm.DB
	mapper ports.IRefreshTokenMapper
	idSvc  domainports.IIDService
}

func NewGormRefreshTokenRepository(
	db *gorm.DB,
	mapper ports.IRefreshTokenMapper,
	idSvc domainports.IIDService,
) *GormRefreshTokenRepository {
	return &GormRefreshTokenRepository{
		db:     db,
		mapper: mapper,
		idSvc:  idSvc,
	}
}

func (r *GormRefreshTokenRepository) Save(token *entities.RefreshToken) error {
	model := r.mapper.ToModel(token)
	if err := r.db.Save(model).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return pgerr.WrapAlreadyExists(err, "refresh token already exists")
		}
		return pgerr.WrapUnavailable(err, "database failure during token save")
	}
	return nil
}

func (r *GormRefreshTokenRepository) GetByID(tokenID valueobjects.TokenID) (*entities.RefreshToken, error) {
	var model models.RefreshToken
	err := r.db.Where("id = ?", tokenID.Value()).First(&model).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, pgerr.WrapUnavailable(err, "failed to fetch token")
	}

	// GATEKEEPER
	if err := model.Validate(r.idSvc); err != nil {
		return nil, err
	}

	return r.mapper.ToDomain(&model), nil
}

func (r *GormRefreshTokenRepository) GetActiveByUserIDAndDeviceID(
	userID valueobjects.UserID,
	deviceID valueobjects.DeviceID,
) ([]*entities.RefreshToken, error) {
	var tokenModels []models.RefreshToken

	// 1. Fetch from DB with explicit 'Active' criteria
	// We use .Find() which doesn't return ErrRecordNotFound if empty,
	// it just returns an empty slice, which is correct for this use case.
	err := r.db.Where(
		"user_id = ? AND device_id = ? AND revoked_at IS NULL AND expires_at > NOW()",
		userID.Value(),
		deviceID.Value(),
	).Find(&tokenModels).Error

	if err != nil {
		return nil, pgerr.WrapUnavailable(err, "failed to query active tokens")
	}

	// 2. Map Models to Domain Entities
	results := make([]*entities.RefreshToken, 0, len(tokenModels))
	for _, model := range tokenModels {
		// Run infrastructure validation (ID format checks, etc.)
		if err := model.Validate(r.idSvc); err != nil {
			// If one record is corrupt, we log/skip or return error based on strictness
			return nil, pgerr.WrapInternal(err, "database contains invalid token data")
		}

		domainEntity := r.mapper.ToDomain(&model)
		results = append(results, domainEntity)
	}

	return results, nil
}
