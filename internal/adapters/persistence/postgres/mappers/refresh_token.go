package mappers

import (
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/valueobjects"
)

type RefreshTokenMapper struct{}

func NewRefreshTokenMapper() *RefreshTokenMapper { return &RefreshTokenMapper{} }

func (m *RefreshTokenMapper) ToDomain(model *models.RefreshToken) *entities.RefreshToken {
	if model == nil {
		return nil
	}

	return entities.ReconstituteRefreshToken(
		valueobjects.ReconstituteTokenID(model.ID),
		valueobjects.ReconstituteUserID(model.UserID),
		valueobjects.ReconstituteDeviceID(model.DeviceID),
		valueobjects.ReconstituteToken(model.Token),
		model.ExpiresAt,
		model.RevokedAt,
		model.CreatedAt,
		model.UpdatedAt,
		model.DeletedAt,
	)
}

func (m *RefreshTokenMapper) ToModel(entity *entities.RefreshToken) *models.RefreshToken {
	if entity == nil {
		return nil
	}

	return &models.RefreshToken{
		ID:        entity.ID().Value(),
		UserID:    entity.UserID().Value(),
		DeviceID:  entity.DeviceID().Value(),
		Token:     entity.Token().Value(),
		ExpiresAt: entity.ExpiresAt(),
		RevokedAt: entity.RevokedAt(),
		CreatedAt: entity.CreatedAt(),
		UpdatedAt: entity.UpdatedAt(),
	}
}
