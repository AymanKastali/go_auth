package valueobjects

import (
	"go_auth/internal/core/domain/derr"
	"strings"
)

type UserID struct {
	value string
}

func NewUserID(value string) (UserID, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return UserID{}, derr.NewValidation.RequiredUserID()
	}
	return UserID{value: trimmed}, nil
}

func (vo UserID) Value() string           { return vo.value }
func (vo UserID) IsEmpty() bool           { return vo.value == "" }
func (vo UserID) Equal(other UserID) bool { return vo.value == other.value }
