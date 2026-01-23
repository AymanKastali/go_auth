package valueobjects

import (
	"go_auth/internal/core/domain/derr"
	"strings"
)

type SessionRenewalTokenSecret struct{ v string }

func NewSessionRenewalTokenSecret(v string) (SessionRenewalTokenSecret, error) {
	trimmed := strings.TrimSpace(v)
	if trimmed == "" {
		return SessionRenewalTokenSecret{}, derr.NewErrSessionRenewalTokenSecretRequired()
	}
	return SessionRenewalTokenSecret{v: trimmed}, nil
}

func (vo SessionRenewalTokenSecret) String() string { return vo.v }
func (vo SessionRenewalTokenSecret) IsEmpty() bool  { return vo.v == "" }
