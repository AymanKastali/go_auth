package factories

import (
	"errors"
	"time"

	"go_auth/src/domain/entities"
	"go_auth/src/domain/value_objects"
)

type DeviceFactory struct{}

func (f *DeviceFactory) New(
	id value_objects.DeviceId,
	userId value_objects.UserId,
	name *string,
	userAgent *string,
	ipAddress *string,
	now time.Time,
) (*entities.Device, error) {

	if id.IsZero() {
		return nil, errors.New("device id is required")
	}

	if userId.IsZero() {
		return nil, errors.New("user id is required")
	}

	return &entities.Device{
		ID:         id,
		UserId:     userId,
		Name:       name,
		UserAgent:  userAgent,
		IPAddress:  ipAddress,
		IsActive:   true,
		CreatedAt:  now,
		LastSeenAt: nil,
		RevokedAt:  nil,
	}, nil
}
