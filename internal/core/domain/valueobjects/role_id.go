package valueobjects

import (
	"go_auth/internal/core/domain/derr"
)

type RoleID struct {
	value string
}

func NewRoleID(value string) (RoleID, error) {
	if value == "" {
		return RoleID{}, derr.NewInvalidValueErr("RoleID")
	}

	return RoleID{value: value}, nil
}

func (vo RoleID) Value() string           { return vo.value }
func (vo RoleID) IsEmpty() bool           { return vo.value == "" }
func (vo RoleID) Equal(other RoleID) bool { return vo.value == other.value }
