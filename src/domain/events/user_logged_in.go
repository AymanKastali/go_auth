package events

import valueobjects "go_auth/src/domain/value_objects"

type UserLoggedIn struct {
	UserID valueobjects.UserID
}
