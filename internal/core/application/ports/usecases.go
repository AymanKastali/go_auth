package ports

import (
	"go_auth/internal/core/application/dto"
	"log/slog"
)

type IAuthUserUseCase interface {
	Execute(l *slog.Logger, userID string) (*dto.AuthUser, error)
}

type ILoginUseCase interface {
	Execute(l *slog.Logger, input dto.LoginInput) (*dto.SessionTokens, error)
}

type ILogoutUseCase interface {
	Execute(l *slog.Logger, rawToken string) error
}

type ISessionRenewalUseCase interface {
	Execute(l *slog.Logger, input dto.SessionRenewalInput) (*dto.SessionTokens, error)
}

type IRegisterUseCase interface {
	Execute(l *slog.Logger, emailStr, passwordStr string) (*dto.RegisteredUserDTO, error)
}

type IUpdateRoleUseCase interface {
	Execute(l *slog.Logger, input dto.ManageRoleInput) error
}

type ISeedAdminUseCase interface {
	Execute(l *slog.Logger, adminEmail, adminPassword string)
}

type ISeedRolesUseCase interface {
	Execute(l *slog.Logger) error
}
