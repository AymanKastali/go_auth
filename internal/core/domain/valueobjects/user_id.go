package valueobjects

import (
	"go_auth/internal/core/domain/derr"
)

type UserID struct {
	value string
}

func NewUserID(value string) (UserID, error) {
	if value == "" {
		return UserID{}, derr.NewInvalidValueErr("UserID")
	}

	return UserID{value: value}, nil
}

func (vo UserID) Value() string           { return vo.value }
func (vo UserID) IsEmpty() bool           { return vo.value == "" }
func (vo UserID) Equal(other UserID) bool { return vo.value == other.value }
