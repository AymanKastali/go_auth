package value_objects

import (
	"go_auth/src/domain/errors"

	"github.com/google/uuid"
)

type DeviceID struct {
	Value uuid.UUID
}

func (id DeviceID) IsZero() bool {
	return id.Value == uuid.Nil
}

func NewDeviceIdFromString(s string) (DeviceID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return DeviceID{}, errors.ErrInvalidDeviceID
	}
	return DeviceID{Value: id}, nil
}
