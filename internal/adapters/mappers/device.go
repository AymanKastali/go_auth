package mappers

import (
	"fmt"
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/valueobjects"
)

type DeviceMapper struct{}

func NewDeviceMapper() *DeviceMapper {
	return &DeviceMapper{}
}

// Map from DB model to domain entity
func (m *DeviceMapper) ToDomain(d *models.Device) (*entities.Device, error) {
	if d == nil {
		return nil, nil
	}

	deviceID, err := valueobjects.DeviceIDFromString(d.ID)
	if err != nil {
		return nil, fmt.Errorf("device mapper: invalid ID '%s': %w", d.ID, err)
	}

	userID, err := valueobjects.UserIDFromString(d.UserID)
	if err != nil {
		return nil, fmt.Errorf("device mapper: invalid User ID '%s': %w", d.UserID, err)
	}

	// Use ReconstituteDevice to respect unexported fields
	return entities.ReconstituteDevice(
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
}

// Map from domain entity to DB model
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
