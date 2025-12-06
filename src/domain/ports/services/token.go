package services

import (
	"go_auth/src/domain/entities"
	valueobjects "go_auth/src/domain/value_objects"
)

type TokenService interface {
	IssueAccessToken(user *entities.User) valueobjects.AccessToken
}
