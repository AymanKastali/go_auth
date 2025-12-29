package use_cases

import (
	"go_auth/internal/application/dto"
)

type LoginUseCasePort interface {
	Login(
		email, password, deviceIDStr, deviceName, userAgent, ipAddress string,
	) (*dto.AuthResponse, error)
}
