package mappers

import (
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/adapters/persistence/postgres/pgerr"
	"go_auth/internal/core/application/interfaces"
	"go_auth/internal/core/domain/entities"
)

type DeviceMapper struct {
	uuidParser interfaces.IUUIDParserService
}

var _ IDeviceMapper = (*DeviceMapper)(nil)

func NewDeviceMapper(
	uuidParser interfaces.IUUIDParserService,
) IDeviceMapper {
	return &DeviceMapper{
		uuidParser: uuidParser,
	}
}

func (m *DeviceMapper) ToDomain(d *models.Device) (*entities.Device, error) {
	if d == nil {
		return nil, pgerr.ErrNotFound
	}

	deviceID, err := m.uuidParser.ParseDeviceID(d.ID)
	if err != nil {
		return nil, err
	}

	userID, err := m.uuidParser.ParseUserID(d.UserID)
	if err != nil {
		return nil, err
	}

	device := entities.ReconstituteDevice(
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

	return device, nil
}

func (m *DeviceMapper) ToModel(d *entities.Device) *models.Device {
	if d == nil {
		return nil
	}

	return &models.Device{
		ID:         d.ID().Value(),
		UserID:     d.UserID().Value(),
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
