package valueobjects

import (
	"go_auth/internal/core/domain/derr"

	"github.com/google/uuid"
)

type UserID struct {
	value uuid.UUID
}

// NewUserID generates a new random UserID
func NewUserID() UserID {
	return UserID{value: uuid.New()}
}

// UserIDFromUUID creates a UserID from an existing UUID
func UserIDFromUUID(u uuid.UUID) UserID {
	return UserID{value: u}
}

// UserIDFromString parses a string into a UserID
func UserIDFromString(u string) (UserID, error) {
	parsed, err := uuid.Parse(u)
	if err != nil {
		// Aligned with V2 factory: NewInvalidValue(attr, msg string)
		return UserID{}, derr.NewInvalidValueErr("user_id", err.Error())
	}

	return UserID{value: parsed}, nil
}

// IsEmpty checks if the UserID is empty/nil
func (vo UserID) IsEmpty() bool {
	return vo.value == uuid.Nil
}

// Equal compares two UserID objects
func (vo UserID) Equal(other UserID) bool {
	return vo.value == other.value
}

// String returns the string representation of the UUID
func (vo UserID) String() string {
	return vo.value.String()
}

// UUID returns the underlying uuid.UUID type for persistence
func (vo UserID) UUID() uuid.UUID {
	return vo.value
}
