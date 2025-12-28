package use_cases

import (
	"go_auth/src/application/dto"
)

type RefreshTokenUseCasePort interface {
	Execute(oldRefreshToken, deviceIdStr string) (*dto.AuthResponse, error)
}
