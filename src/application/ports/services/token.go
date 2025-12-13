package services

import (
	valueobjects "go_auth/src/domain/value_objects"
)

type TokenServicePort interface {
	IssueAccessToken(userID string, roles []string) (valueobjects.AccessToken, error)
	IssueRefreshToken(userID string) (valueobjects.RefreshToken, error)
	// IssueAccessToken(user *entities.User) (valueobjects.AccessToken, error)
	// IssueRefreshToken(user *entities.User) (valueobjects.RefreshToken, error)
}
