package valueobjects

import (
	"go_auth/internal/core/domain/derr"
	"strings"
)

type RoleID struct {
	value string
}

func NewRoleID(value string) (RoleID, error) {
	trimmed := strings.TrimSpace(value)

	if trimmed == "" {
		return RoleID{}, derr.ErrRoleIDRequired()
	}
	return RoleID{value: trimmed}, nil
}

func (vo RoleID) Value() string           { return vo.value }
func (vo RoleID) IsEmpty() bool           { return vo.value == "" }
func (vo RoleID) Equal(other RoleID) bool { return vo.value == other.value }
