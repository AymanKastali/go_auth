package mappers

import (
	"fmt"
	"go_auth/src/domain/entities"
	"go_auth/src/infra/persistence/postgres/models"
)

type DeviceMapper struct {
	uuidMapper *UUIDMapper
}

func NewDeviceMapper(
	uuidMapper *UUIDMapper,
) *DeviceMapper {
	return &DeviceMapper{
		uuidMapper: uuidMapper,
	}
}

func (m *DeviceMapper) ToDomain(d *models.Device) (*entities.Device, error) {
	if d == nil {
		return nil, nil
	}

	deviceId, err := m.uuidMapper.DeviceIdFromString(d.ID)
	if err != nil {
		return nil, fmt.Errorf("device mapper: invalid ID '%s': %w", d.ID, err)
	}

	userId, err := m.uuidMapper.UserIdFromString(d.UserId)
	if err != nil {
		return nil, fmt.Errorf("device mapper: invalid User ID '%s': %w", d.UserId, err)
	}

	return &entities.Device{
		ID:         deviceId,
		UserId:     userId,
		Name:       d.Name,
		UserAgent:  d.UserAgent,
		IPAddress:  d.IPAddress,
		IsActive:   d.IsActive,
		CreatedAt:  d.CreatedAt,
		LastSeenAt: d.LastSeenAt,
		RevokedAt:  d.RevokedAt,
	}, nil
}

func (m *DeviceMapper) ToModel(d *entities.Device) *models.Device {
	if d == nil {
		return nil
	}

	return &models.Device{
		ID:         d.ID.Value.String(),
		UserId:     d.UserId.Value.String(),
		Name:       d.Name,
		UserAgent:  d.UserAgent,
		IPAddress:  d.IPAddress,
		IsActive:   d.IsActive,
		LastSeenAt: d.LastSeenAt,
		RevokedAt:  d.RevokedAt,
	}
}
