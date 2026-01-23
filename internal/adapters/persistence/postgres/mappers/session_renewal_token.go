package mappers

import (
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/valueobjects"
	"time"
)

type SessionRenewalTokenMapper struct{}

func NewSessionRenewalTokenMapper() *SessionRenewalTokenMapper { return &SessionRenewalTokenMapper{} }

func (m *SessionRenewalTokenMapper) ToDomain(model *models.SessionRenewalToken) *entities.SessionRenewalToken {
	if model == nil {
		return nil
	}

	var revokedAt *valueobjects.Timepoint
	if model.RevokedAt != nil {
		tp := valueobjects.ReconstituteTimepoint(*model.RevokedAt)
		revokedAt = &tp
	}

	return entities.ReconstituteSessionRenewalToken(
		valueobjects.ReconstituteSessionRenewalRawTokenID(model.ID),
		valueobjects.ReconstituteUserID(model.UserID),
		valueobjects.ReconstituteDeviceID(model.DeviceID),
		valueobjects.ReconstituteSessionRenewalHashedToken(model.Hash),
		valueobjects.ReconstituteTimepoint(model.CreatedAt),
		valueobjects.ReconstituteTimepoint(model.ExpiresAt),
		revokedAt,
	)
}

func (m *SessionRenewalTokenMapper) ToModel(entity *entities.SessionRenewalToken) *models.SessionRenewalToken {
	if entity == nil {
		return nil
	}

	var revokedAtPtr *time.Time
	if entity.RevokedAt() != nil {
		t := entity.RevokedAt().Time()
		revokedAtPtr = &t
	}

	return &models.SessionRenewalToken{
		ID:        entity.ID().String(),
		UserID:    entity.UserID().String(),
		DeviceID:  entity.DeviceID().String(),
		Hash:      entity.SessionRenewalHashedToken().String(),
		CreatedAt: entity.CreatedAt().Time(),
		ExpiresAt: entity.ExpiresAt().Time(),
		RevokedAt: revokedAtPtr,
	}
}
