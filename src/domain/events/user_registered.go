package events

import valueobjects "go_auth/src/domain/value_objects"

type UserRegistered struct {
	UserID valueobjects.UserID
}
