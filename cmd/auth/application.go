package main

import (
	"go_auth/internal/adapters"
	"go_auth/internal/adapters/persistence/postgres"
	"go_auth/internal/core/application"
)

// applicationInfra holds adapter implementations of application-layer ports
// (e.g. email, transactions). These are NOT domain services.
type applicationInfra struct {
	emailSvc  application.IEmailService
	txManager application.ITransactionManager
}

func newApplicationInfra(cfg *adapters.Config, pf *postgres.PersistenceFactory) applicationInfra {
	return applicationInfra{
		emailSvc:  adapters.NewEmailService(cfg.Email),
		txManager: pf.NewTransactionManager(),
	}
}

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

func newUseCases(d domainServices, infra applicationInfra) useCases {
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
			infra.emailSvc,
			infra.txManager,
			d.clock,
		),
		changePassword: application.NewChangePasswordUseCase(
			d.userRepo,
			d.accountManager,
			d.clock,
		),
		resetPassword: application.NewResetPasswordUseCase(
			d.accountManager,
			infra.txManager,
			d.clock,
		),
	}
}
