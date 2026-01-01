package use_cases

import (
	"go_auth/internal/core/application/dto"
)

type AuthenticatedUserUseCasePort interface {
	GetAuthUser(userID string) (*dto.AuthenticatedUser, error)
}
