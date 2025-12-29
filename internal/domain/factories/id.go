package factories

import (
	"fmt"
	"go_auth/internal/domain/valueobjects"

	"github.com/google/uuid"
)

type IDFactory struct{}

func (f *IDFactory) NewUserID() valueobjects.UserID {
	return valueobjects.UserID{Value: uuid.New()}
}

func (f *IDFactory) NewTokenID() valueobjects.TokenID {
	return valueobjects.TokenID{Value: uuid.New()}
}

func (f *IDFactory) NewDeviceId() valueobjects.DeviceID {
	return valueobjects.DeviceID{Value: uuid.New()}
}

func (f *IDFactory) UserIDFromString(s string) (valueobjects.UserID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return valueobjects.UserID{}, fmt.Errorf("invalid UserID '%s': %w", s, err)
	}
	return valueobjects.UserID{Value: id}, nil
}

func (f *IDFactory) TokenIDFromString(s string) (valueobjects.TokenID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return valueobjects.TokenID{}, fmt.Errorf("invalid TokenID '%s': %w", s, err)
	}
	return valueobjects.TokenID{Value: id}, nil
}

func (f *IDFactory) DeviceIDFromString(s string) (valueobjects.DeviceID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return valueobjects.DeviceID{}, fmt.Errorf("invalid DeviceID '%s': %w", s, err)
	}
	return valueobjects.DeviceID{Value: id}, nil
}
