package use_cases

import (
	"go_auth/src/application/dto"
)

type RegisterUseCasePort interface {
	Register(email, password string) (*dto.RegisteredUserDTO, error)
}
