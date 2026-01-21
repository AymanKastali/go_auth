package valueobjects

import (
	"go_auth/internal/core/domain/derr"
	"strings"
)

type DeviceID struct {
	value string
}

func NewDeviceID(value string) (DeviceID, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return DeviceID{}, derr.NewErrDeviceIDRequired()
	}
	return DeviceID{value: trimmed}, nil
}

func ReconstituteDeviceID(s string) DeviceID { return DeviceID{value: s} }

func (vo DeviceID) Value() string             { return vo.value }
func (vo DeviceID) IsEmpty() bool             { return vo.value == "" }
func (vo DeviceID) Equal(other DeviceID) bool { return vo.value == other.value }
