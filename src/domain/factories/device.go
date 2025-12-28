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
	userId value_objects.UserId,
	name *string,
	userAgent *string,
	ipAddress *string,
	now time.Time,
) (*entities.Device, error) {

	deviceId := f.idFactory.NewDeviceId()

	return &entities.Device{
		ID:         deviceId,
		UserId:     userId,
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
