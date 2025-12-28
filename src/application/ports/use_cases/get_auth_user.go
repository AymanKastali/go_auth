package use_cases

import (
	"go_auth/src/application/dto"
)

type AuthenticatedUserUseCasePort interface {
	GetAuthUser(userID string) (*dto.AuthenticatedUser, error)
}
