package valueobjects

import (
	"go_auth/internal/core/domain/derr"
	"strings"
)

type RoleID struct{ v string }

func NewRoleID(v string) (RoleID, error) {
	trimmed := strings.TrimSpace(v)

	if trimmed == "" {
		return RoleID{}, derr.NewErrRoleIDRequired()
	}
	return RoleID{v: trimmed}, nil
}

func ReconstituteRoleID(s string) RoleID { return RoleID{v: s} }

func (vo RoleID) String() string          { return vo.v }
func (vo RoleID) IsEmpty() bool           { return vo.v == "" }
func (vo RoleID) Equal(other RoleID) bool { return vo.v == other.v }
