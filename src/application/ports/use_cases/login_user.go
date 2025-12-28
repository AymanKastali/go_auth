package use_cases

import (
	"go_auth/src/application/dto"
)

type AuthenticatedUserUseCasePort interface {
	Execute(userId string) (*dto.AuthenticatedUser, error)
}
