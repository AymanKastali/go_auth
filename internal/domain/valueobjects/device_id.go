package valueobjects

import (
	"go_auth/internal/domain/domainerr"

	"github.com/google/uuid"
)

type DeviceID struct {
	Value uuid.UUID
}

func (id DeviceID) IsZero() bool {
	return id.Value == uuid.Nil
}

func NewDeviceIdFromString(s string) (DeviceID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return DeviceID{}, domainerr.ErrInvalidDeviceID
	}
	return DeviceID{Value: id}, nil
}
