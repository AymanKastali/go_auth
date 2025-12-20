package factories

import (
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
