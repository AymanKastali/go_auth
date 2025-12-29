package use_cases

import (
	"go_auth/internal/application/dto"
)

type AuthenticatedUserUseCasePort interface {
	GetAuthUser(userID string) (*dto.AuthenticatedUser, error)
}
