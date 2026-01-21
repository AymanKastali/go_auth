package mappers

import (
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/valueobjects"
	"time"
)

type RefreshTokenMapper struct{}

func NewRefreshTokenMapper() *RefreshTokenMapper { return &RefreshTokenMapper{} }

func (m *RefreshTokenMapper) ToDomain(model *models.RefreshToken) *entities.RefreshToken {
	if model == nil {
		return nil
	}

	var revokedAt *valueobjects.Timepoint
	if model.RevokedAt != nil {
		tp := valueobjects.ReconstituteTimepoint(*model.RevokedAt)
		revokedAt = &tp
	}

	return entities.ReconstituteRefreshToken(
		valueobjects.ReconstituteTokenID(model.ID),
		valueobjects.ReconstituteUserID(model.UserID),
		valueobjects.ReconstituteDeviceID(model.DeviceID),
		valueobjects.ReconstituteHashedToken(model.Hash),
		valueobjects.ReconstituteTimepoint(model.CreatedAt),
		valueobjects.ReconstituteTimepoint(model.ExpiresAt),
		revokedAt,
	)
}

func (m *RefreshTokenMapper) ToModel(entity *entities.RefreshToken) *models.RefreshToken {
	if entity == nil {
		return nil
	}

	var revokedAtPtr *time.Time
	if entity.RevokedAt() != nil {
		t := entity.RevokedAt().Value()
		revokedAtPtr = &t
	}

	return &models.RefreshToken{
		ID:        entity.ID().Value(),
		UserID:    entity.UserID().Value(),
		DeviceID:  entity.DeviceID().Value(),
		Hash:      entity.HashedToken().Value(),
		CreatedAt: entity.CreatedAt().Value(),
		ExpiresAt: entity.ExpiresAt().Value(),
		RevokedAt: revokedAtPtr,
	}
}
