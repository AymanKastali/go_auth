package valueobjects

import (
	"go_auth/internal/core/domain/derr"
)

type DeviceID struct {
	value string
}

func NewDeviceID(value string) (DeviceID, error) {
	if value == "" {
		return DeviceID{}, derr.NewInvalidValueErr("DeviceID")
	}

	return DeviceID{value: value}, nil
}

func (vo DeviceID) Value() string             { return vo.value }
func (vo DeviceID) IsEmpty() bool             { return vo.value == "" }
func (vo DeviceID) Equal(other DeviceID) bool { return vo.value == other.value }
