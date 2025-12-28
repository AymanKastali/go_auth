package factories

import (
	"fmt"
	"go_auth/src/domain/value_objects"

	"github.com/google/uuid"
)

type IDFactory struct{}

func (f *IDFactory) NewUserID() value_objects.UserID {
	return value_objects.UserID{Value: uuid.New()}
}

func (f *IDFactory) NewTokenID() value_objects.TokenID {
	return value_objects.TokenID{Value: uuid.New()}
}

func (f *IDFactory) NewDeviceId() value_objects.DeviceID {
	return value_objects.DeviceID{Value: uuid.New()}
}

func (f *IDFactory) UserIDFromString(s string) (value_objects.UserID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return value_objects.UserID{}, fmt.Errorf("invalid UserID '%s': %w", s, err)
	}
	return value_objects.UserID{Value: id}, nil
}

func (f *IDFactory) TokenIDFromString(s string) (value_objects.TokenID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return value_objects.TokenID{}, fmt.Errorf("invalid TokenID '%s': %w", s, err)
	}
	return value_objects.TokenID{Value: id}, nil
}

func (f *IDFactory) DeviceIDFromString(s string) (value_objects.DeviceID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return value_objects.DeviceID{}, fmt.Errorf("invalid DeviceID '%s': %w", s, err)
	}
	return value_objects.DeviceID{Value: id}, nil
}
