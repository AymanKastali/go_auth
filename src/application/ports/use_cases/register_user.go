package use_cases

import (
	"go_auth/src/application/dto"
)

type RegisterUseCasePort interface {
	Execute(email, password string) (*dto.AuthResponse, error)
}
