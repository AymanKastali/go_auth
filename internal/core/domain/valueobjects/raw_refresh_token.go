package valueobjects

import (
	"go_auth/internal/core/domain/derr"
	"strings"
)

type RawRefreshToken struct {
	tokenID TokenID
	secret  string
}

func NewRawRefreshToken(tokenID TokenID, secret string) (RawRefreshToken, error) {
	if tokenID.Value() == "" {
		return RawRefreshToken{}, derr.NewErrInvalidRefreshTokenFormat()
	}
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return RawRefreshToken{}, derr.NewErrInvalidRefreshTokenFormat()
	}
	return RawRefreshToken{tokenID: tokenID, secret: secret}, nil
}

func ParseRawRefreshToken(raw string) (RawRefreshToken, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return RawRefreshToken{}, derr.NewErrRefreshTokenRequired()
	}

	parts := strings.Split(trimmed, ".")
	if len(parts) != 2 {
		return RawRefreshToken{}, derr.NewErrInvalidRefreshTokenFormat()
	}

	tokenID, err := NewTokenID(parts[0])
	if err != nil {
		return RawRefreshToken{}, derr.NewErrInvalidRefreshTokenFormat()
	}

	secret := strings.TrimSpace(parts[1])
	if secret == "" {
		return RawRefreshToken{}, derr.NewErrInvalidRefreshTokenFormat()
	}

	return NewRawRefreshToken(tokenID, secret)
}

func (vo RawRefreshToken) TokenID() TokenID { return vo.tokenID }
func (vo RawRefreshToken) Secret() string   { return vo.secret }
func (vo RawRefreshToken) String() string   { return vo.tokenID.Value() + "." + vo.secret }
func (vo RawRefreshToken) IsEmpty() bool    { return vo.tokenID.IsEmpty() || vo.secret == "" }
