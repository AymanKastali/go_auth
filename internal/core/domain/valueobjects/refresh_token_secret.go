package valueobjects

import (
	"go_auth/internal/core/domain/derr"
	"strings"
)

type RefreshTokenSecret struct{ v string }

func NewRefreshTokenSecret(v string) (RefreshTokenSecret, error) {
	trimmed := strings.TrimSpace(v)
	if trimmed == "" {
		return RefreshTokenSecret{}, derr.NewErrRefreshTokenSecretRequired()
	}
	return RefreshTokenSecret{v: trimmed}, nil
}

func (vo RefreshTokenSecret) String() string { return vo.v }
func (vo RefreshTokenSecret) IsEmpty() bool  { return vo.v == "" }
