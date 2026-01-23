package ports

import (
	"context"
	"go_auth/internal/core/application/dto"
)

type IAuthUserUseCase interface {
	Execute(
		c context.Context, userID string,
	) (*dto.AuthUser, error)
}

type ILoginUseCase interface {
	Execute(
		c context.Context, email, password string,
	) (*dto.SessionTokens, error)
}
type ILogoutUseCase interface {
	Execute(
		c context.Context, sessionRenewalToken string,
	) error
}

type ISessionRenewalUseCase interface {
	Execute(
		c context.Context, oldSessionRenewalToken string,
	) (*dto.SessionTokens, error)
}

type IRegisterUseCase interface {
	Execute(
		c context.Context, email, password string,
	) (*dto.RegisteredUserDTO, error)
}

type IUpdateRoleUseCase interface {
	Execute(
		c context.Context, req dto.ManageRoleInput,
	) error
}
