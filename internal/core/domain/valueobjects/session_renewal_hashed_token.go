package valueobjects

import (
	"go_auth/internal/core/domain/derr"
	"strings"
)

type SessionRenewalHashedToken struct{ v string }

func NewSessionRenewalHashedToken(v string) (SessionRenewalHashedToken, error) {
	trimmed := strings.TrimSpace(v)

	if trimmed == "" {
		return SessionRenewalHashedToken{}, derr.NewErrTokenHashRequired()
	}
	return SessionRenewalHashedToken{v: trimmed}, nil
}

func ReconstituteSessionRenewalHashedToken(v string) SessionRenewalHashedToken {
	return SessionRenewalHashedToken{v: v}
}

func (vo SessionRenewalHashedToken) String() string { return vo.v }
func (vo SessionRenewalHashedToken) IsEmpty() bool  { return vo.v == "" }
func (vo SessionRenewalHashedToken) Equal(other SessionRenewalHashedToken) bool {
	return vo.v == other.v
}
