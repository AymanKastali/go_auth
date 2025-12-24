package factories

import (
	"time"

	"go_auth/src/domain/entities"
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
	name *string,
	userAgent *string,
	ipAddress *string,
	now time.Time,
) (*entities.Device, error) {

	deviceId := f.idFactory.NewDeviceId()
	userId := f.idFactory.NewUserID()

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
