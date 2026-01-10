package valueobjects

import (
	"go_auth/internal/core/domain/derr"

	"github.com/google/uuid"
)

type DeviceID struct {
	value uuid.UUID
}

// NewDeviceID generates a new random DeviceID
func NewDeviceID() DeviceID {
	return DeviceID{value: uuid.New()}
}

// DeviceIDFromUUID creates a DeviceID from an existing UUID
func DeviceIDFromUUID(u uuid.UUID) DeviceID {
	return DeviceID{value: u}
}

// DeviceIDFromString parses a string into a DeviceID
func DeviceIDFromString(u string) (DeviceID, error) {
	parsed, err := uuid.Parse(u)
	if err != nil {
		// Matches V2 factory: NewInvalidValue(attr, msg string)
		// We wrap the original error message into the domain message
		return DeviceID{}, derr.NewInvalidValueErr("DeviceID")
	}

	return DeviceID{value: parsed}, nil
}

// IsEmpty checks if the DeviceID is empty/nil
func (vo DeviceID) IsEmpty() bool {
	return vo.value == uuid.Nil
}

// Equal compares two DeviceID objects
func (vo DeviceID) Equal(other DeviceID) bool {
	return vo.value == other.value
}

// String returns the string representation of the UUID
func (vo DeviceID) String() string {
	return vo.value.String()
}

// UUID returns the underlying uuid.UUID type
func (vo DeviceID) UUID() uuid.UUID {
	return vo.value
}
