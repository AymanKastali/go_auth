package events

import "go_auth/internal/domain/valueobjects"

type UserRegistered struct {
	UserID valueobjects.UserID
}
