package valueobjects

import (
	"go_auth/internal/core/domain/derr"
	"strings"
)

type RawRefreshToken struct {
	tokenID TokenID
	secret  string
}

func NewRawRefreshToken(value string) (RawRefreshToken, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return RawRefreshToken{}, derr.ErrTokenRequired()
	}

	parts := strings.Split(trimmed, ".")
	if len(parts) != 2 {
		return RawRefreshToken{}, derr.ErrInvalidTokenFormat()
	}

	tokenID, err := NewTokenID(parts[0])
	if err != nil {
		return RawRefreshToken{}, err
	}

	secret := strings.TrimSpace(parts[1])
	if secret == "" {
		return RawRefreshToken{}, derr.ErrInvalidTokenFormat()
	}

	return RawRefreshToken{
		tokenID: tokenID,
		secret:  secret,
	}, nil
}

func (vo RawRefreshToken) Value() string { return vo.value }
