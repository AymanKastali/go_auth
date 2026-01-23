package valueobjects

import (
	"go_auth/internal/core/domain/derr"
	"strings"
)

type SessionRenewalRawTokenID struct{ v string }

func NewSessionRenewalRawTokenID(v string) (SessionRenewalRawTokenID, error) {
	trimmed := strings.TrimSpace(v)
	if trimmed == "" {
		return SessionRenewalRawTokenID{}, derr.NewErrSessionRenewalRawTokenIDRequired()
	}
	return SessionRenewalRawTokenID{v: trimmed}, nil
}

func ReconstituteSessionRenewalRawTokenID(s string) SessionRenewalRawTokenID {
	return SessionRenewalRawTokenID{v: s}
}

func (vo SessionRenewalRawTokenID) String() string                            { return vo.v }
func (vo SessionRenewalRawTokenID) IsEmpty() bool                             { return vo.v == "" }
func (vo SessionRenewalRawTokenID) Equal(other SessionRenewalRawTokenID) bool { return vo.v == other.v }
