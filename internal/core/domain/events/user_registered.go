package events

import "go_auth/internal/core/domain/valueobjects"

type UserRegistered struct {
	UserID valueobjects.UserID
}
