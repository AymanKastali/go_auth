package mappers

import (
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/adapters/persistence/postgres/pgerr"
	"go_auth/internal/core/application/interfaces"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/valueobjects"
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
	entity := "Device"
	if d == nil {
		return nil, nil
	}

	deviceID, err := valueobjects.DeviceIDFromString(d.ID)
	if err != nil {
		return nil, pgerr.NewDataCorruptionErr(entity, d.ID, err)
	}

	userID, err := m.uuidParser.ParseUserID(d.UserID)
	if err != nil {
		return nil, pgerr.NewDataCorruptionErr(entity, d.UserID, err)
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
		return nil, pgerr.NewDataCorruptionErr(entity, d.ID, err)
	}

	return device, nil
}

func (m *DeviceMapper) ToModel(d *entities.Device) *models.Device {
	if d == nil {
		return nil
	}

	return &models.Device{
		ID:         d.ID().String(),
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
