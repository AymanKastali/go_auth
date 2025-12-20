package events

import "go_auth/src/domain/value_objects"

type UserLoggedIn struct {
	UserID value_objects.UserID
}
