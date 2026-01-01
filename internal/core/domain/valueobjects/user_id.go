package valueobjects

import (
	"go_auth/internal/core/domain/domainerr"

	"github.com/google/uuid"
)

const userIDFromStringOp = "UserID.FromString"

type UserID struct {
	value uuid.UUID
}

func NewUserID() UserID {
	return UserID{value: uuid.New()}
}

func UserIDFromUUID(u uuid.UUID) UserID {
	return UserID{value: u}
}

func UserIDFromString(u string) (UserID, error) {
	parsed, err := uuid.Parse(u)
	if err != nil {
		return UserID{}, domainerr.NewDomainInvalidValueError("user id", userIDFromStringOp, err)
	}

	return UserID{value: parsed}, nil
}

func (vo UserID) IsZero() bool {
	return vo.value == uuid.Nil
}

func (vo UserID) Equal(other UserID) bool {
	return vo.value == other.value
}

func (vo UserID) String() string {
	return vo.value.String()
}
