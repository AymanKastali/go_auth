package valueobjects

import (
	"go_auth/internal/core/domain/derr"
	"strings"
)

type DeviceFingerprint struct {
	value string
}

func NewDeviceFingerprint(value string) (DeviceFingerprint, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return DeviceFingerprint{}, derr.NewErrDeviceFingerprintRequired()
	}
	return DeviceFingerprint{value: trimmed}, nil
}

func ReconstituteDeviceFingerprint(s string) DeviceFingerprint { return DeviceFingerprint{value: s} }

func (vo DeviceFingerprint) Value() string                      { return vo.value }
func (vo DeviceFingerprint) IsEmpty() bool                      { return vo.value == "" }
func (vo DeviceFingerprint) Equal(other DeviceFingerprint) bool { return vo.value == other.value }
