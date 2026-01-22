package valueobjects

import (
	"go_auth/internal/core/domain/derr"
	"strings"
)

type DeviceID struct{ v string }

func NewDeviceID(v string) (DeviceID, error) {
	trimmed := strings.TrimSpace(v)
	if trimmed == "" {
		return DeviceID{}, derr.NewErrDeviceIDRequired()
	}
	return DeviceID{v: trimmed}, nil
}

func ReconstituteDeviceID(s string) DeviceID { return DeviceID{v: s} }

func (vo DeviceID) String() string            { return vo.v }
func (vo DeviceID) IsEmpty() bool             { return vo.v == "" }
func (vo DeviceID) Equal(other DeviceID) bool { return vo.v == other.v }
