package events

import "go_auth/internal/domain/valueobjects"

type UserLoggedIn struct {
	UserID valueobjects.UserID
}
