package events

import "go_auth/src/domain/value_objects"

type UserRegistered struct {
	UserId value_objects.UserId
}
