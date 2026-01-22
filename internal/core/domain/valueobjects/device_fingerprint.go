package valueobjects

import (
	"go_auth/internal/core/domain/derr"
	"strings"
)

type DeviceFingerprint struct{ v string }

func NewDeviceFingerprint(v string) (DeviceFingerprint, error) {
	trimmed := strings.TrimSpace(v)
	if trimmed == "" {
		return DeviceFingerprint{}, derr.NewErrDeviceFingerprintRequired()
	}
	return DeviceFingerprint{v: trimmed}, nil
}

func ReconstituteDeviceFingerprint(s string) DeviceFingerprint { return DeviceFingerprint{v: s} }

func (vo DeviceFingerprint) String() string                     { return vo.v }
func (vo DeviceFingerprint) IsEmpty() bool                      { return vo.v == "" }
func (vo DeviceFingerprint) Equal(other DeviceFingerprint) bool { return vo.v == other.v }
