package ports

import (
	"go_auth/internal/core/application/dto"
)

type IAuthUserUseCase interface {
	Execute(
		requestID, userID string,
	) (*dto.AuthUser, error)
}

type ILoginUseCase interface {
	Execute(
		requestID, email, password, deviceIDStr, deviceName, userAgent, ipAddress string,
	) (*dto.AuthResponse, error)
}
type ILogoutUseCase interface {
	Execute(
		requestID, refreshToken string,
	) error
}

type IRefreshTokenUseCase interface {
	Execute(
		requestID, oldRefreshToken, deviceIDStr string,
	) (*dto.AuthResponse, error)
}

type IRegisterUseCase interface {
	Execute(
		requestID, email, password string,
	) (*dto.RegisteredUserDTO, error)
}

type IUpdateRoleUseCase interface {
	Execute(
		requestID string, req dto.ManageRoleInput,
	) error
}
