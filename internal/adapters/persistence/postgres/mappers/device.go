package mappers

import (
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/adapters/persistence/postgres/pgerr"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/valueobjects"
)

type DeviceMapper struct{}

func NewDeviceMapper() *DeviceMapper {
	return &DeviceMapper{}
}

func (m *DeviceMapper) ToDomain(d *models.Device) (*entities.Device, error) {
	entity := "Device"
	if d == nil {
		return nil, nil
	}

	deviceID, err := valueobjects.DeviceIDFromString(d.ID)
	if err != nil {
		return nil, pgerr.NewDataCorruptionErr(entity, d.ID, "ID", err)
	}

	userID, err := valueobjects.UserIDFromString(d.UserID)
	if err != nil {
		return nil, pgerr.NewDataCorruptionErr(entity, d.ID, "UserID", err)
	}

	device, err := entities.ReconstituteDevice(
		deviceID,
		userID,
		d.Name,
		d.UserAgent,
		d.IPAddress,
		d.IsActive,
		d.CreatedAt,
		d.UpdatedAt,
		d.LastSeenAt,
		d.RevokedAt,
	)
	if err != nil {
		return nil, pgerr.NewDataCorruptionErr(entity, d.ID, "Aggregate", err)
	}

	return device, nil
}

func (m *DeviceMapper) ToModel(d *entities.Device) *models.Device {
	if d == nil {
		return nil
	}

	return &models.Device{
		ID:         d.ID().String(),
		UserID:     d.UserID().String(),
		Name:       d.Name(),
		UserAgent:  d.UserAgent(),
		IPAddress:  d.IPAddress(),
		IsActive:   d.IsActive(),
		CreatedAt:  d.CreatedAt(),
		UpdatedAt:  d.UpdatedAt(),
		LastSeenAt: d.LastSeenAt(),
		RevokedAt:  d.RevokedAt(),
	}
}
