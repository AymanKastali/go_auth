package mappers

import (
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/valueobjects"
)

type DeviceMapper struct{}

func NewDeviceMapper() *DeviceMapper { return &DeviceMapper{} }

func (m *DeviceMapper) ToDomain(model *models.Device) *entities.Device {
	if model == nil {
		return nil
	}

	return entities.ReconstituteDevice(
		valueobjects.ReconstituteDeviceID(model.ID),
		valueobjects.ReconstituteUserID(model.UserID),
		model.Name,
		model.UserAgent,
		model.IPAddress,
		model.IsActive,
		model.CreatedAt,
		model.UpdatedAt,
		model.LastSeenAt,
		model.RevokedAt,
	)
}

func (m *DeviceMapper) ToModel(entity *entities.Device) *models.Device {
	if entity == nil {
		return nil
	}

	return &models.Device{
		ID:         entity.ID().Value(),
		UserID:     entity.UserID().Value(),
		Name:       entity.Name(),
		UserAgent:  entity.UserAgent(),
		IPAddress:  entity.IPAddress(),
		IsActive:   entity.IsActive(),
		CreatedAt:  entity.CreatedAt(),
		UpdatedAt:  entity.UpdatedAt(),
		LastSeenAt: entity.LastSeenAt(),
		RevokedAt:  entity.RevokedAt(),
	}
}
