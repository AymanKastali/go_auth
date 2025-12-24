package factories

import (
	"fmt"
	"go_auth/src/domain/value_objects"

	"github.com/google/uuid"
)

type IDFactory struct{}

func (f *IDFactory) NewUserID() value_objects.UserId {
	return value_objects.UserId{Value: uuid.New()}
}

func (f *IDFactory) NewTokenID() value_objects.TokenId {
	return value_objects.TokenId{Value: uuid.New()}
}

func (f *IDFactory) NewDeviceId() value_objects.DeviceId {
	return value_objects.DeviceId{Value: uuid.New()}
}

func (f *IDFactory) UserIDFromString(s string) (value_objects.UserId, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return value_objects.UserId{}, fmt.Errorf("invalid UserId '%s': %w", s, err)
	}
	return value_objects.UserId{Value: id}, nil
}

func (f *IDFactory) TokenIDFromString(s string) (value_objects.TokenId, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return value_objects.TokenId{}, fmt.Errorf("invalid TokenId '%s': %w", s, err)
	}
	return value_objects.TokenId{Value: id}, nil
}

func (f *IDFactory) DeviceIDFromString(s string) (value_objects.DeviceId, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return value_objects.DeviceId{}, fmt.Errorf("invalid DeviceId '%s': %w", s, err)
	}
	return value_objects.DeviceId{Value: id}, nil
}
