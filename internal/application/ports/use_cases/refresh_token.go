package use_cases

import (
	"go_auth/internal/application/dto"
)

type RefreshTokenUseCasePort interface {
	RefreshToken(oldRefreshToken, deviceIdStr string) (*dto.AuthResponse, error)
}
