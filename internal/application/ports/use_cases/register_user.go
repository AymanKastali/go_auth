package use_cases

import (
	"go_auth/internal/application/dto"
)

type RegisterUseCasePort interface {
	Register(email, password string) (*dto.RegisteredUserDTO, error)
}
