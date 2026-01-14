package ports

import (
	"go_auth/internal/core/application/dto"
)

type AuthUserUseCasePort interface {
	Execute(requestID, userID string) (*dto.AuthUser, error)
}

type LoginUseCasePort interface {
	Execute(
		requestID, email, password, deviceIDStr, deviceName, userAgent, ipAddress string,
	) (*dto.AuthResponse, error)
}
type LogoutUseCasePort interface {
	Execute(requestID, refreshToken string) error
}

type RefreshTokenUseCasePort interface {
	Execute(
		requestID, oldRefreshToken, deviceIDStr string,
	) (*dto.AuthResponse, error)
}

type RegisterUseCasePort interface {
	Execute(requestID, email, password string) (*dto.RegisteredUserDTO, error)
}

type UpdateRoleUseCasePort interface {
	Execute(requestID string, req dto.ManageRoleInput) error
}
