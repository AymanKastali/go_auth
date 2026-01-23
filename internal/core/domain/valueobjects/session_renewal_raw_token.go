package valueobjects

import (
	"go_auth/internal/core/domain/derr"
	"strings"
)

type SessionRenewalRawToken struct {
	id     SessionRenewalTokenID
	secret SessionRenewalTokenSecret
}

func NewSessionRenewalRawToken(tokenID SessionRenewalTokenID, secret SessionRenewalTokenSecret) (SessionRenewalRawToken, error) {
	if tokenID.IsEmpty() {
		return SessionRenewalRawToken{}, derr.NewErrInvalidSessionRenewalTokenFormat()
	}
	if secret.IsEmpty() {
		return SessionRenewalRawToken{}, derr.NewErrInvalidSessionRenewalTokenFormat()
	}
	return SessionRenewalRawToken{id: tokenID, secret: secret}, nil
}

func ParseSessionRenewalRawToken(raw string) (SessionRenewalRawToken, error) {
	parts := strings.Split(strings.TrimSpace(raw), ".")
	if len(parts) != 2 {
		return SessionRenewalRawToken{}, derr.NewErrInvalidSessionRenewalTokenFormat()
	}

	tokenID, err := NewSessionRenewalTokenID(parts[0])
	if err != nil {
		return SessionRenewalRawToken{}, err
	}

	secret, err := NewSessionRenewalTokenSecret(parts[1])
	if err != nil {
		return SessionRenewalRawToken{}, err
	}

	return NewSessionRenewalRawToken(tokenID, secret)
}

func (vo SessionRenewalRawToken) ID() SessionRenewalTokenID         { return vo.id }
func (vo SessionRenewalRawToken) Secret() SessionRenewalTokenSecret { return vo.secret }
func (vo SessionRenewalRawToken) String() string {
	return vo.id.String() + "." + vo.secret.String()
}
func (vo SessionRenewalRawToken) IsEmpty() bool { return vo.id.IsEmpty() || vo.secret.IsEmpty() }
