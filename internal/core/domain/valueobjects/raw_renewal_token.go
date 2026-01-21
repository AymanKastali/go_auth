package valueobjects

import (
	"strings"
)

type RawRenewalToken struct{ value string }

func NewRawRenewalToken(value string) (RawRenewalToken, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return RawRenewalToken{}, nil
	}
	return RawRenewalToken{value: trimmed}, nil
}

func (vo RawRenewalToken) Value() string { return vo.value }
