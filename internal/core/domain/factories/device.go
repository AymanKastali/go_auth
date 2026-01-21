package factories

import (
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
)

type defaultDeviceFactory struct {
	idSvc    ports.IIDService
	clockSvc ports.IClockService
}

func NewDefaultDeviceFactory(
	idSvc ports.IIDService,
	clockSvc ports.IClockService,
) *defaultDeviceFactory {
	return &defaultDeviceFactory{
		idSvc:    idSvc,
		clockSvc: clockSvc,
	}
}

func (f *defaultDeviceFactory) New(
	fingerprint valueobjects.DeviceFingerprint,
	userID valueobjects.UserID,
	name *string,
	userAgent *string,
	ip *string,
	isActive bool,
	now valueobjects.Timepoint,
) (*entities.Device, error) {
	deviceID := f.idSvc.Generate()
	deviceIDVO, err := valueobjects.NewDeviceID(deviceID)
	if err != nil {
		return nil, err
	}
	return entities.NewDevice(
		deviceIDVO,
		fingerprint,
		userID,
		name,
		userAgent,
		ip,
		isActive,
		now,
	)
}
