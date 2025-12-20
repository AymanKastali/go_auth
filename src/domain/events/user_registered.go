package events

import value_objects "go_auth/src/domain/value_objects"

type UserRegistered struct {
	UserID value_objects.UserID
}
