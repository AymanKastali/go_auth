package valueobjects

import (
	"go_auth/internal/core/domain/derr"
	"strings"
)

type SessionRenewalTokenID struct{ v string }

func NewSessionRenewalTokenID(v string) (SessionRenewalTokenID, error) {
	trimmed := strings.TrimSpace(v)
	if trimmed == "" {
		return SessionRenewalTokenID{}, derr.NewErrSessionRenewalTokenIDRequired()
	}
	return SessionRenewalTokenID{v: trimmed}, nil
}

func ReconstituteSessionRenewalTokenID(s string) SessionRenewalTokenID {
	return SessionRenewalTokenID{v: s}
}

func (vo SessionRenewalTokenID) String() string                         { return vo.v }
func (vo SessionRenewalTokenID) IsEmpty() bool                          { return vo.v == "" }
func (vo SessionRenewalTokenID) Equal(other SessionRenewalTokenID) bool { return vo.v == other.v }
