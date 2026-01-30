package domain

import "fmt"

var (
	ZeroDeviceIdentity    = DeviceIdentity{}
	ZeroDeviceFingerprint = DeviceFingerprint{}
)

// --- DeviceIdentity ---
type DeviceIdentity struct {
	ipAddress string
	os        string
	browser   string
	model     string
	language  string
	userAgent string
	isMobile  bool
}

func NewDeviceIdentity(ip, os, browser, model, lang, ua string, isMobile bool) (DeviceIdentity, error) {
	if ip == "" {
		return ZeroDeviceIdentity, ErrDeviceIPRequired
	}
	if ua == "" {
		return ZeroDeviceIdentity, ErrDeviceUARequired
	}
	return DeviceIdentity{
		ipAddress: ip,
		os:        os,
		browser:   browser,
		model:     model,
		language:  lang,
		userAgent: ua,
		isMobile:  isMobile,
	}, nil
}

func ReconstituteDeviceIdentity(ip, os, browser, model, lang, ua string, isMobile bool) DeviceIdentity {
	return DeviceIdentity{
		ipAddress: ip,
		os:        os,
		browser:   browser,
		model:     model,
		language:  lang,
		userAgent: ua,
		isMobile:  isMobile,
	}
}

func (d DeviceIdentity) Fingerprint() DeviceFingerprint {
	return NewDeviceFingerprintFromIdentity(d.userAgent, d.ipAddress, d.language)
}

func (d DeviceIdentity) DisplayName() string {
	// If it's a mobile device and we have a specific model name, use it.
	if d.isMobile && d.model != "" && d.model != "Generic" {
		return fmt.Sprintf("%s (%s)", d.model, d.browser)
	}

	// Default to the browser and OS (e.g., "Chrome on Windows")
	return fmt.Sprintf("%s on %s", d.browser, d.os)
}
func (d DeviceIdentity) IPAddress() string { return d.ipAddress }
func (d DeviceIdentity) OS() string        { return d.os }
func (d DeviceIdentity) Browser() string   { return d.browser }
func (d DeviceIdentity) Model() string     { return d.model }
func (d DeviceIdentity) Language() string  { return d.language }
func (d DeviceIdentity) UserAgent() string { return d.userAgent }
func (d DeviceIdentity) IsMobile() bool    { return d.isMobile }

// --- DeviceFingerprint ---
type DeviceFingerprint struct{ value string }

func NewDeviceFingerprintFromIdentity(ua, ip, lang string) DeviceFingerprint {
	val := fmt.Sprintf("%s|%s|%s", ua, ip, lang)
	return DeviceFingerprint{value: val}
}

func NewDeviceFingerprint(value string) (DeviceFingerprint, error) {
	if value == "" {
		return ZeroDeviceFingerprint, ErrDeviceFingerprintRequired
	}
	return DeviceFingerprint{value: value}, nil
}

func (vo DeviceFingerprint) String() string                     { return vo.value }
func (vo DeviceFingerprint) Equal(other DeviceFingerprint) bool { return vo.value == other.value }
