package valueobjects

type DeviceFingerprint struct {
	value string
}

func NewDeviceFingerprint(value string) DeviceFingerprint {
	return DeviceFingerprint{value: value}
}

func (d DeviceFingerprint) Value() string {
	return d.value
}
