package repositories

import (
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/valueobjects"
	"time"
)

type DeviceRepositoryPort interface {
	GetByID(deviceID valueobjects.DeviceID) (*entities.Device, error)

	Upsert(device *entities.Device) error

	Revoke(deviceID valueobjects.DeviceID, revokedAt time.Time) error

	GetByUserID(userID valueobjects.UserID) ([]*entities.Device, error)
}
