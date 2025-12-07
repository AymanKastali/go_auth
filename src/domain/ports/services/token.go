package services

import (
	"go_auth/src/domain/entities"
	valueobjects "go_auth/src/domain/value_objects"
)

type TokenService interface {
	IssueAccessToken(user *entities.User) (valueobjects.AccessToken, error)
	IssueRefreshToken(user *entities.User) (valueobjects.RefreshToken, error)

	// Stateless validation
	ParseAccessToken(token string) (valueobjects.UserID, error)
	ParseRefreshToken(token string) (valueobjects.UserID, error)
}
