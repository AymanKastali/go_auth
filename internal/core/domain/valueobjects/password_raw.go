package valueobjects

import (
	"go_auth/internal/core/domain/derr"
	"strings"
)

type RawPassword struct{ v string }

func NewRawPassword(v string) (RawPassword, error) {
	trimmed := strings.TrimSpace(v)

	if trimmed == "" {
		return RawPassword{}, derr.NewErrPasswordRequired()
	}
	return RawPassword{v: v}, nil
}

func (vo RawPassword) String() string { return vo.v }
