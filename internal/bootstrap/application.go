package bootstrap

import (
	"go_auth/internal/adapters"
	"go_auth/internal/core/application"
)

type UseCases struct {
	// auth
	SeedSA   application.ISeedSuperAdminUseCase
	Register application.IRegisterUseCase
	Login    application.ILoginUseCase
	Refresh  application.IRefreshTokenUseCase
	Logout   application.ILogoutUseCase
	Validate application.IValidateAccessUseCase

	// user
	FindByEmail    application.IFindUserByEmailUseCase
	GetByID        application.IGetUserByIDUseCase
	GetMe          application.IGetMeUseCase
	UpdateMe       application.IUpdateMeUseCase
	ChangePassword application.IChangePasswordUseCase
	ForgotPassword application.IForgotPasswordUseCase
	ResetPassword  application.IResetPasswordUseCase
}

func NewUseCases(d DomainServices) UseCases {
	return UseCases{
		//

		Register: application.NewRegisterUseCase(
			d.UserRepo,
			d.RegistrationSvc,
			d.PasswordManager,
			d.IDGen,
			d.Clock,
		),
		SeedSA: application.NewSeedSuperAdminUseCase(
			d.UserRepo,
			d.RegistrationSvc,
			d.PasswordManager,
			d.IDGen,
			d.Clock,
		),
		Login: application.NewLoginUseCase(
			d.UserRepo,
			d.AuthenticationSvc,
			d.AccessManager,
			d.Clock,
		),
		Refresh: application.NewRefreshTokenUseCase(
			d.UserRepo,
			d.AuthenticationSvc,
			d.AccessManager,
			d.Clock,
		),
		Validate: application.NewValidateAccessUseCase(
			d.AccessManager,
			d.Clock,
		),
		Logout: application.NewLogoutUseCase(
			d.UserRepo, d.Clock,
		),

		// user
		FindByEmail: application.NewFindUserByEmailUseCase(d.UserRepo),
		GetByID:     application.NewGetUserByIDUseCase(d.UserRepo),
		GetMe:       application.NewGetMeUseCase(d.UserRepo),
		UpdateMe:    application.NewUpdateMeUseCase(d.UserRepo, d.Clock),
		ForgotPassword: application.NewForgotPasswordUseCase(
			d.UserRepo,
			d.RecoveryRepo,
			d.AccountManager,
			d.EmailSvc,
			d.TxManager,
			d.Clock,
		),
		ChangePassword: application.NewChangePasswordUseCase(
			d.UserRepo,
			d.AccountManager,
			d.Clock,
		),
		ResetPassword: application.NewResetPasswordUseCase(
			d.AccountManager,
			d.TxManager,
			d.Clock,
		),
	}
}

type ApplicationServices struct {
	IDGen application.IIDGenerator
}

func NewApplicationServices() ApplicationServices {
	return ApplicationServices{
		IDGen: adapters.NewULIDGenerator(),
	}
}
