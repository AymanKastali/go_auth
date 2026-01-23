package valueobjects

import (
	"go_auth/internal/core/domain/derr"
	"strings"
)

type SessionRenewalRawTokenSecret struct{ v string }

func NewSessionRenewalRawTokenSecret(v string) (SessionRenewalRawTokenSecret, error) {
	trimmed := strings.TrimSpace(v)
	if trimmed == "" {
		return SessionRenewalRawTokenSecret{}, derr.NewErrSessionRenewalRawTokenSecretRequired()
	}
	return SessionRenewalRawTokenSecret{v: trimmed}, nil
}

func (vo SessionRenewalRawTokenSecret) String() string { return vo.v }
func (vo SessionRenewalRawTokenSecret) IsEmpty() bool  { return vo.v == "" }
