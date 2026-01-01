package events

import "go_auth/internal/core/domain/valueobjects"

type UserLoggedIn struct {
	UserID valueobjects.UserID
}
