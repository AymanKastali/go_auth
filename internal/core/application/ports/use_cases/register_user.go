package use_cases

import (
	"go_auth/internal/core/application/dto"
)

type RegisterUseCasePort interface {
	Register(email, password string) (*dto.RegisteredUserDTO, error)
}
