package mappers

import (
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/valueobjects"
)

type RenewalTokenMapper struct{}

func NewRenewalTokenMapper() *RenewalTokenMapper { return &RenewalTokenMapper{} }

func (m *RenewalTokenMapper) ToDomain(model *models.RenewalToken) *entities.RenewalToken {
	if model == nil {
		return nil
	}

	return entities.ReconstituteRenewalToken(
		valueobjects.ReconstituteTokenID(model.ID),
		valueobjects.ReconstituteUserID(model.UserID),
		valueobjects.ReconstituteDeviceID(model.DeviceID),
		valueobjects.ReconstituteHashedToken(model.Hash),
		model.ExpiresAt,
		model.RevokedAt,
		model.CreatedAt,
	)
}

func (m *RenewalTokenMapper) ToModel(entity *entities.RenewalToken) *models.RenewalToken {
	if entity == nil {
		return nil
	}

	return &models.RenewalToken{
		ID:        entity.ID().Value(),
		UserID:    entity.UserID().Value(),
		DeviceID:  entity.DeviceID().Value(),
		Hash:      entity.Hash().Value(),
		ExpiresAt: entity.ExpiresAt(),
		RevokedAt: entity.RevokedAt(),
		CreatedAt: entity.CreatedAt(),
	}
}
