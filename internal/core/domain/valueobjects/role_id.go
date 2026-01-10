package valueobjects

import (
	"go_auth/internal/core/domain/derr"

	"github.com/google/uuid"
)

type RoleID struct {
	value uuid.UUID
}

func NewRoleID() RoleID {
	return RoleID{value: uuid.New()}
}

func RoleIDFromUUID(u uuid.UUID) RoleID {
	return RoleID{value: u}
}

func RoleIDFromString(u string) (RoleID, error) {
	parsed, err := uuid.Parse(u)
	if err != nil {
		return RoleID{}, derr.NewInvalidValueErr("RoleID")
	}

	return RoleID{value: parsed}, nil
}

func (vo RoleID) IsEmpty() bool {
	return vo.value == uuid.Nil
}

func (vo RoleID) Equal(other RoleID) bool {
	return vo.value == other.value
}

func (vo RoleID) String() string {
	return vo.value.String()
}

func (vo RoleID) UUID() uuid.UUID {
	return vo.value
}
