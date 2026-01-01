package valueobjects

import (
	"go_auth/internal/core/domain/domainerr"

	"github.com/google/uuid"
)

const tokenIDFromStringOp = "TokenID.FromString"

type TokenID struct {
	value uuid.UUID
}

func NewTokenID() TokenID {
	return TokenID{value: uuid.New()}
}

func TokenIDFromUUID(u uuid.UUID) TokenID {
	return TokenID{value: u}
}

func TokenIDFromString(u string) (TokenID, error) {
	parsed, err := uuid.Parse(u)
	if err != nil {
		return TokenID{}, domainerr.InvalidValueError("device id", tokenIDFromStringOp, err)
	}

	return TokenID{value: parsed}, nil
}

func (vo TokenID) IsZero() bool {
	return vo.value == uuid.Nil
}

func (vo TokenID) Equal(other TokenID) bool {
	return vo.value == other.value
}

func (vo TokenID) String() string {
	return vo.value.String()
}
