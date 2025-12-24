package repositories

import (
	"go_auth/src/domain/entities"
	"go_auth/src/domain/value_objects"
	"time"
)

type DeviceRepositoryPort interface {
	GetByID(deviceID value_objects.DeviceId) (*entities.Device, error)

	// Upsert creates or updates a device
	Upsert(device *entities.Device) error

	// Revoke deactivates a device
	Revoke(deviceID value_objects.DeviceId, revokedAt time.Time) error

	// GetByUserID retrieves all devices for a user
	GetByUserID(userID value_objects.UserId) ([]*entities.Device, error)
}
