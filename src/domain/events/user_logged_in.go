package events

import "go_auth/src/domain/value_objects"

type UserLoggedIn struct {
	UserId value_objects.UserId
}
