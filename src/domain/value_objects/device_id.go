package value_objects

import (
	"go_auth/src/domain/errors"

	"github.com/google/uuid"
)

type DeviceId struct {
	Value uuid.UUID
}

func (id DeviceId) IsZero() bool {
	return id.Value == uuid.Nil
}

func NewDeviceIdFromString(s string) (DeviceId, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return DeviceId{}, errors.ErrInvalidDeviceID
	}
	return DeviceId{Value: id}, nil
}
