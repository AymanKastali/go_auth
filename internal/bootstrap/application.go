package bootstrap

import "go_auth/internal/core/application"

type UseCases struct {
	// auth
	SeedSA   application.ISeedSuperAdmin
	Register application.IRegisterUseCase
	Login    application.ILoginUseCase
	Refresh  application.IRefreshTokenUseCase
	Logout   application.ILogoutUseCase
	Validate application.IValidateAccessUseCase

	// user
	FindByEmail application.IFindUserByEmail
	GetByID     application.IGetUserByID
	GetCurrent  application.IGetCurrentUser
}

func NewUseCases(d DomainServices) UseCases {
	return UseCases{
		Register: application.NewRegisterUseCase(d.UserRepo, d.RegisterSvc),
		Login:    application.NewLoginUseCase(d.UserRepo, d.AuthSvc, d.SessionSvc, d.AccessGrantor),
		Refresh:  application.NewRefreshTokenUseCase(d.UserRepo, d.RefreshSvc, d.AccessGrantor),
		Logout:   application.NewLogoutUseCase(d.UserRepo, d.Clock),
		Validate: application.NewValidateAccessUseCase(d.AccessSvc, d.UserRepo, d.Clock),
		SeedSA:   application.NewSeedSuperAdminUseCase(d.UserRepo, d.RegisterSvc),
		// user
		FindByEmail: application.NewFindUserByEmailUseCase(d.UserRepo),
		GetByID:     application.NewGetUserByIDUseCase(d.UserRepo),
		GetCurrent:  application.NewGetCurrentUserUseCase(d.UserRepo),
	}
}
