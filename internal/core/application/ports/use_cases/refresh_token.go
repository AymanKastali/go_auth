package use_cases

import (
	"go_auth/internal/core/application/dto"
)

type RefreshTokenUseCasePort interface {
	RefreshToken(oldRefreshToken, deviceIDStr string) (*dto.AuthResponse, error)
}
