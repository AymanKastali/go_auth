package use_cases

import (
	"go_auth/src/application/dto"
)

type RefreshTokenUseCasePort interface {
	RefreshToken(oldRefreshToken, deviceIdStr string) (*dto.AuthResponse, error)
}
