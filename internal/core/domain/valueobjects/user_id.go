package valueobjects

import (
	"go_auth/internal/core/domain/derr"
	"strings"
)

type UserID struct{ v string }

func NewUserID(v string) (UserID, error) {
	trimmed := strings.TrimSpace(v)
	if trimmed == "" {
		return UserID{}, derr.NewErrUserIDRequired()
	}
	return UserID{v: trimmed}, nil
}

func ReconstituteUserID(s string) UserID { return UserID{v: s} }

func (vo UserID) String() string          { return vo.v }
func (vo UserID) IsEmpty() bool           { return vo.v == "" }
func (vo UserID) Equal(other UserID) bool { return vo.v == other.v }
