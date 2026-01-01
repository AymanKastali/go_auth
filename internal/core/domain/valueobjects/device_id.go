package valueobjects

import (
	"go_auth/internal/core/domain/domainerr"

	"github.com/google/uuid"
)

const deviceIDFromStringOp = "DeviceID.FromString"

type DeviceID struct {
	value uuid.UUID
}

func NewDeviceID() DeviceID {
	return DeviceID{value: uuid.New()}
}

func DeviceIDFromUUID(u uuid.UUID) DeviceID {
	return DeviceID{value: u}
}

func DeviceIDFromString(u string) (DeviceID, error) {
	parsed, err := uuid.Parse(u)
	if err != nil {
		return DeviceID{}, domainerr.InvalidValueError("device id", deviceIDFromStringOp, err)
	}

	return DeviceID{value: parsed}, nil
}

func (vo DeviceID) IsZero() bool {
	return vo.value == uuid.Nil
}

func (vo DeviceID) Equal(other DeviceID) bool {
	return vo.value == other.value
}

func (vo DeviceID) String() string {
	return vo.value.String()
}
