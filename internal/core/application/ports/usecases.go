package ports

import (
	"go_auth/internal/core/application/dto"
)

type AuthUserUseCasePort interface {
	Execute(traceID, userID string) (*dto.AuthUser, error)
}

type LoginUseCasePort interface {
	Execute(
		traceID, email, password, deviceIDStr, deviceName, userAgent, ipAddress string,
	) (*dto.AuthResponse, error)
}
type LogoutUseCasePort interface {
	Execute(traceID, refreshToken string) error
}

type RefreshTokenUseCasePort interface {
	Execute(
		traceID, oldRefreshToken, deviceIDStr string,
	) (*dto.AuthResponse, error)
}

type RegisterUseCasePort interface {
	Execute(traceID, email, password string) (*dto.RegisteredUserDTO, error)
}

type UpdateRoleUseCasePort interface {
	Execute(traceID string, req dto.ManageRoleInput) error
}
