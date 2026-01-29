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
			d.RegisterPolicy,
			d.PasswordPolicy,
			d.PasswordSvc,
			d.UserFactory,
			d.IDGen,
			d.Clock,
		),
		SeedSA: application.NewSeedSuperAdminUseCase(
			d.UserRepo,
			d.PasswordPolicy,
			d.PasswordSvc,
			d.UserFactory,
			d.IDGen,
			d.Clock,
		),
		Login: application.NewLoginUseCase(
			d.UserRepo,
			d.PasswordSvc,
			d.IDGen,
			d.TokenSvc,
			d.SessionFactory,
			d.SessionPolicy,
			d.Clock,
			d.AccessSvc,
			d.AccessPolicy,
		),
		Refresh: application.NewRefreshTokenUseCase(
			d.UserRepo,
			d.TokenSvc,
			d.Clock,
			d.AccessSvc,
			d.AccessPolicy,
		),
		Validate: application.NewValidateAccessUseCase(
			d.AccessSvc,
			d.UserRepo,
			d.Clock,
		),
		Logout: application.NewLogoutUseCase(
			d.UserRepo, d.Clock,
		),

		//

		// user
		FindByEmail: application.NewFindUserByEmailUseCase(d.UserRepo),
		GetByID:     application.NewGetUserByIDUseCase(d.UserRepo),
		GetMe:       application.NewGetMeUseCase(d.UserRepo),
		UpdateMe:    application.NewUpdateMeUseCase(d.UserRepo, d.Clock),
		ForgotPassword: application.NewForgotPasswordUseCase(d.UserRepo,
			d.ForgotPasswordSvc, // Correct Service
			d.EmailSvc,          // Email infrastructure
			d.TxManager,         // For atomic token creation
			d.Clock),
		ChangePassword: application.NewChangePasswordUseCase(d.UserRepo, d.ChangePasswordSvc),
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
