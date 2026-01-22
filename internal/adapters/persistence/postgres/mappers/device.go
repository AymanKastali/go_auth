package mappers

import (
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/valueobjects"
	"time"
)

type DeviceMapper struct{}

func NewDeviceMapper() *DeviceMapper { return &DeviceMapper{} }

func (m *DeviceMapper) ToDomain(model *models.Device) *entities.Device {
	if model == nil {
		return nil
	}

	var revokedAt *valueobjects.Timepoint
	if model.RevokedAt != nil {
		tp := valueobjects.ReconstituteTimepoint(*model.RevokedAt)
		revokedAt = &tp
	}

	var deletedAt *valueobjects.Timepoint
	if model.DeletedAt != nil {
		tp := valueobjects.ReconstituteTimepoint(*model.DeletedAt)
		deletedAt = &tp
	}

	return entities.ReconstituteDevice(
		valueobjects.ReconstituteDeviceID(model.ID),
		valueobjects.ReconstituteDeviceFingerprint(model.Fingerprint),
		valueobjects.ReconstituteUserID(model.UserID),
		model.Name,
		model.UserAgent,
		model.IPAddress,
		model.IsActive,
		valueobjects.ReconstituteTimepoint(model.CreatedAt),
		valueobjects.ReconstituteTimepoint(model.UpdatedAt),
		valueobjects.ReconstituteTimepoint(model.LastSeenAt),
		revokedAt,
		deletedAt,
	)
}

func (m *DeviceMapper) ToModel(entity *entities.Device) *models.Device {
	if entity == nil {
		return nil
	}

	var revokedAtPtr *time.Time
	if entity.RevokedAt() != nil {
		t := entity.RevokedAt().Time()
		revokedAtPtr = &t
	}

	var deletedAtPtr *time.Time
	if entity.DeletedAt() != nil {
		t := entity.DeletedAt().Time()
		deletedAtPtr = &t
	}

	return &models.Device{
		ID:          entity.ID().String(),
		Fingerprint: entity.Fingerprint().String(),
		UserID:      entity.UserID().String(),
		Name:        entity.Name(),
		UserAgent:   entity.UserAgent(),
		IPAddress:   entity.IPAddress(),
		IsActive:    entity.IsActive(),
		CreatedAt:   entity.CreatedAt().Time(),
		UpdatedAt:   entity.UpdatedAt().Time(),
		LastSeenAt:  entity.LastSeenAt().Time(),
		RevokedAt:   revokedAtPtr,
		DeletedAt:   deletedAtPtr,
	}
}
