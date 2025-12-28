package repositories

import (
	"go_auth/src/domain/entities"
	"go_auth/src/domain/value_objects"
	"time"
)

type DeviceRepositoryPort interface {
	GetByID(deviceID value_objects.DeviceID) (*entities.Device, error)

	Upsert(device *entities.Device) error

	Revoke(deviceID value_objects.DeviceID, revokedAt time.Time) error

	GetByUserID(userID value_objects.UserID) ([]*entities.Device, error)
}
