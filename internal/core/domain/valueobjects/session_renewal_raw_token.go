package valueobjects

import (
	"go_auth/internal/core/domain/derr"
	"strings"
)

var ZeroSessionRenewalRawToken SessionRenewalRawToken = SessionRenewalRawToken{}

type SessionRenewalRawToken struct {
	id     SessionRenewalRawTokenID
	secret SessionRenewalRawTokenSecret
}

func NewSessionRenewalRawToken(id SessionRenewalRawTokenID, secret SessionRenewalRawTokenSecret) (SessionRenewalRawToken, error) {
	if id.IsEmpty() {
		return SessionRenewalRawToken{}, derr.NewErrInvalidSessionRenewalTokenFormat()
	}
	if secret.IsEmpty() {
		return SessionRenewalRawToken{}, derr.NewErrInvalidSessionRenewalTokenFormat()
	}
	return SessionRenewalRawToken{id: id, secret: secret}, nil
}

func ParseSessionRenewalRawToken(raw string) (SessionRenewalRawToken, error) {
	parts := strings.Split(strings.TrimSpace(raw), ".")
	if len(parts) != 2 {
		return SessionRenewalRawToken{}, derr.NewErrInvalidSessionRenewalTokenFormat()
	}

	id, err := NewSessionRenewalRawTokenID(parts[0])
	if err != nil {
		return SessionRenewalRawToken{}, err
	}

	secret, err := NewSessionRenewalRawTokenSecret(parts[1])
	if err != nil {
		return SessionRenewalRawToken{}, err
	}

	return NewSessionRenewalRawToken(id, secret)
}

func (vo SessionRenewalRawToken) ID() SessionRenewalRawTokenID         { return vo.id }
func (vo SessionRenewalRawToken) Secret() SessionRenewalRawTokenSecret { return vo.secret }
func (vo SessionRenewalRawToken) String() string {
	return vo.id.String() + "." + vo.secret.String()
}
func (vo SessionRenewalRawToken) IsEmpty() bool { return vo.id.IsEmpty() || vo.secret.IsEmpty() }
