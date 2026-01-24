package valueobjects

import (
	"fmt"
	"go_auth/internal/core/domain/derr"
	"strings"
)

type DeviceFingerprintTraits struct {
	UserAgent string
	CPU       string
	Memory    string
	Screen    string
}

func NewDeviceFingerprintTraits(m map[string]string) (DeviceFingerprintTraits, error) {
	traits := DeviceFingerprintTraits{
		UserAgent: strings.TrimSpace(m["ua"]),
		CPU:       strings.TrimSpace(m["cpu"]),
		Memory:    strings.TrimSpace(m["mem"]),
		Screen:    strings.TrimSpace(m["res"]),
	}

	if traits.UserAgent == "" && traits.CPU == "" && traits.Memory == "" && traits.Screen == "" {
		return DeviceFingerprintTraits{}, derr.NewErrDeviceFingerprintTraits()
	}

	return traits, nil
}

func (t DeviceFingerprintTraits) Bytes() []byte {
	raw := fmt.Sprintf("UA:%s|CPU:%s|MEM:%s|SCR:%s",
		strings.ToLower(strings.TrimSpace(t.UserAgent)),
		strings.TrimSpace(t.CPU),
		strings.TrimSpace(t.Memory),
		strings.TrimSpace(t.Screen),
	)
	return []byte(raw)
}
