package factories

import (
	"time"

	"go_auth/src/domain/entities"
	"go_auth/src/domain/value_objects"
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
	userID value_objects.UserID,
	deviceID value_objects.DeviceID,
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
