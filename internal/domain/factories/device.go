package factories

import (
	"time"

	"go_auth/internal/domain/entities"
	"go_auth/internal/domain/valueobjects"
)

type DeviceFactory struct {
	idFactory IDFactory
}

func NewDeviceFactory(
	idFactory IDFactory,
) *DeviceFactory {
	return &DeviceFactory{
		idFactory: idFactory,
	}
}

func (f *DeviceFactory) New(
	userID valueobjects.UserID,
	deviceID valueobjects.DeviceID,
	name *string,
	userAgent *string,
	ipAddress *string,
	now time.Time,
) (*entities.Device, error) {

	return &entities.Device{
		ID:         deviceID,
		UserID:     userID,
		Name:       name,
		UserAgent:  userAgent,
		IPAddress:  ipAddress,
		IsActive:   true,
		CreatedAt:  now,
		UpdatedAt:  now,
		LastSeenAt: &now,
		RevokedAt:  nil,
	}, nil
}
