package valueobjects

import (
	"go_auth/internal/core/domain/derr"

	"github.com/google/uuid"
)

type TokenID struct {
	value uuid.UUID
}

// NewTokenID generates a new random TokenID
func NewTokenID() TokenID {
	return TokenID{value: uuid.New()}
}

// TokenIDFromUUID creates a TokenID from an existing UUID
func TokenIDFromUUID(u uuid.UUID) TokenID {
	return TokenID{value: u}
}

// TokenIDFromString parses a string into a TokenID
func TokenIDFromString(u string) (TokenID, error) {
	parsed, err := uuid.Parse(u)
	if err != nil {
		// Aligned with V2 factory: NewInvalidValue(attr, msg string)
		return TokenID{}, derr.NewInvalidValueErr("token_id", err.Error())
	}

	return TokenID{value: parsed}, nil
}

// IsEmpty checks if the TokenID is empty/nil
func (vo TokenID) IsEmpty() bool {
	return vo.value == uuid.Nil
}

// Equal compares two TokenID objects
func (vo TokenID) Equal(other TokenID) bool {
	return vo.value == other.value
}

// String returns the string representation of the UUID
func (vo TokenID) String() string {
	return vo.value.String()
}

// UUID returns the underlying uuid.UUID type
func (vo TokenID) UUID() uuid.UUID {
	return vo.value
}
