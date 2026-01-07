package ports

import (
	"go_auth/internal/core/application/dto"
)

type AuthUserUseCasePort interface {
	Execute(userID string) (*dto.AuthUser, error)
}

type LoginUseCasePort interface {
	Execute(
		email, password, deviceIDStr, deviceName, userAgent, ipAddress string,
	) (*dto.AuthResponse, error)
}
type LogoutUseCasePort interface {
	Execute(refreshToken string) error
}

type RefreshTokenUseCasePort interface {
	Execute(
		oldRefreshToken, deviceIDStr string,
	) (*dto.AuthResponse, error)
}

type RegisterUseCasePort interface {
	Execute(email, password string) (*dto.RegisteredUserDTO, error)
}

type UpdateRoleUseCasePort interface {
	Execute(req dto.ManageRoleInput) error
}
