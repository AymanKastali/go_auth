package valueobjects

import (
	"go_auth/internal/core/domain/derr"
	"strings"
)

type RawRefreshToken struct {
	tokenID TokenID
	secret  RefreshTokenSecret
}

func NewRawRefreshToken(tokenID TokenID, secret RefreshTokenSecret) (RawRefreshToken, error) {
	if tokenID.IsEmpty() {
		return RawRefreshToken{}, derr.NewErrInvalidRefreshTokenFormat()
	}
	if secret.IsEmpty() {
		return RawRefreshToken{}, derr.NewErrInvalidRefreshTokenFormat()
	}
	return RawRefreshToken{tokenID: tokenID, secret: secret}, nil
}

func ParseRawRefreshToken(raw string) (RawRefreshToken, error) {
	parts := strings.Split(strings.TrimSpace(raw), ".")
	if len(parts) != 2 {
		return RawRefreshToken{}, derr.NewErrInvalidRefreshTokenFormat()
	}

	tokenID, err := NewTokenID(parts[0])
	if err != nil {
		return RawRefreshToken{}, err
	}

	secret, err := NewRefreshTokenSecret(parts[1])
	if err != nil {
		return RawRefreshToken{}, err
	}

	return NewRawRefreshToken(tokenID, secret)
}

func (vo RawRefreshToken) TokenID() TokenID           { return vo.tokenID }
func (vo RawRefreshToken) Secret() RefreshTokenSecret { return vo.secret }
func (vo RawRefreshToken) String() string             { return vo.tokenID.String() + "." + vo.secret.String() }
func (vo RawRefreshToken) IsEmpty() bool              { return vo.tokenID.IsEmpty() || vo.secret.IsEmpty() }
