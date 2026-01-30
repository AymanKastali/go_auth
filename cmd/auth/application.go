package main

import (
	"go_auth/internal/adapters"
	"go_auth/internal/adapters/http/fiberapp"
	"go_auth/internal/core/application"
)

type useCases struct {
	// auth
	seedSA   application.ISeedSuperAdminUseCase
	register application.IRegisterUseCase
	login    application.ILoginUseCase
	refresh  application.IRefreshTokenUseCase
	logout   application.ILogoutUseCase
	validate application.IValidateAccessUseCase

	// user
	findByEmail    application.IFindUserByEmailUseCase
	getByID        application.IGetUserByIDUseCase
	getMe          application.IGetMeUseCase
	updateMe       application.IUpdateMeUseCase
	changePassword application.IChangePasswordUseCase
	forgotPassword application.IForgotPasswordUseCase
	resetPassword  application.IResetPasswordUseCase
}

func newUseCases(d domainServices) useCases {
	return useCases{
		register: application.NewRegisterUseCase(
			d.userRepo,
			d.registrationSvc,
			d.passwordManager,
			d.idGen,
			d.clock,
		),
		seedSA: application.NewSeedSuperAdminUseCase(
			d.userRepo,
			d.registrationSvc,
			d.passwordManager,
			d.idGen,
			d.clock,
		),
		login: application.NewLoginUseCase(
			d.userRepo,
			d.authenticationSvc,
			d.accessManager,
			d.clock,
		),
		refresh: application.NewRefreshTokenUseCase(
			d.userRepo,
			d.authenticationSvc,
			d.accessManager,
			d.clock,
		),
		validate: application.NewValidateAccessUseCase(
			d.accessManager,
			d.clock,
		),
		logout: application.NewLogoutUseCase(
			d.userRepo, d.clock,
		),

		// user
		findByEmail: application.NewFindUserByEmailUseCase(d.userRepo),
		getByID:     application.NewGetUserByIDUseCase(d.userRepo),
		getMe:       application.NewGetMeUseCase(d.userRepo),
		updateMe:    application.NewUpdateMeUseCase(d.userRepo, d.clock),
		forgotPassword: application.NewForgotPasswordUseCase(
			d.userRepo,
			d.recoveryRepo,
			d.accountManager,
			d.emailSvc,
			d.txManager,
			d.clock,
		),
		changePassword: application.NewChangePasswordUseCase(
			d.userRepo,
			d.accountManager,
			d.clock,
		),
		resetPassword: application.NewResetPasswordUseCase(
			d.accountManager,
			d.txManager,
			d.clock,
		),
	}
}

type applicationServices struct {
	idGen fiberapp.IIDGenerator
}

func newApplicationServices() applicationServices {
	return applicationServices{
		idGen: adapters.NewULIDGenerator(),
	}
}
