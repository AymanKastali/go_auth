package main

import (
	"log/slog"

	"go_auth/internal/adapters"
	"go_auth/internal/adapters/persistence/postgres"
	"go_auth/internal/core/application"
	"go_auth/internal/core/domain"
)

// applicationInfra holds adapter implementations of application-layer ports
// (e.g. email, transactions). These are NOT domain services.
type applicationInfra struct {
	emailSvc   application.IEmailService
	txManager  application.ITransactionManager
	dispatcher application.IEventDispatcher
	userQuery  application.IUserQueryPort
}

func newApplicationInfra(cfg *adapters.Config, pf *postgres.PersistenceFactory, logger *slog.Logger) applicationInfra {
	return applicationInfra{
		emailSvc:   adapters.NewEmailService(cfg.Email),
		txManager:  pf.NewTransactionManager(),
		dispatcher: adapters.NewLoggingEventDispatcher(logger),
		userQuery:  pf.NewUserQueryAdapter(),
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

	// policies
	publicPolicies application.IGetPublicPoliciesUseCase
}

func newUseCases(d domainServices, infra applicationInfra, cfg *adapters.Config) useCases {
	return useCases{
		register: application.NewRegisterUseCase(
			d.userRepo,
			d.registrationSvc,
			d.passwordManager,
			d.idGen,
			d.clock,
			infra.dispatcher,
		),
		seedSA: application.NewSeedSuperAdminUseCase(
			d.userRepo,
			d.registrationSvc,
			d.passwordManager,
			d.idGen,
			d.clock,
			infra.dispatcher,
		),
		login: application.NewLoginUseCase(
			d.userRepo,
			d.authenticationSvc,
			d.accessManager,
			d.clock,
			infra.dispatcher,
		),
		refresh: application.NewRefreshTokenUseCase(
			d.userRepo,
			d.authenticationSvc,
			d.accessManager,
			d.clock,
			infra.dispatcher,
		),
		validate: application.NewValidateAccessUseCase(
			d.accessManager,
			d.clock,
		),
		logout: application.NewLogoutUseCase(
			d.userRepo, d.clock, infra.dispatcher,
		),

		// user
		findByEmail: application.NewFindUserByEmailUseCase(infra.userQuery),
		getByID:     application.NewGetUserByIDUseCase(infra.userQuery),
		getMe:       application.NewGetMeUseCase(infra.userQuery),
		updateMe:    application.NewUpdateMeUseCase(d.userRepo, d.clock, infra.dispatcher),
		forgotPassword: application.NewForgotPasswordUseCase(
			d.userRepo,
			d.recoveryRepo,
			d.accountManager,
			infra.emailSvc,
			infra.txManager,
			d.clock,
			infra.dispatcher,
		),
		changePassword: application.NewChangePasswordUseCase(
			d.userRepo,
			d.accountManager,
			d.clock,
			infra.dispatcher,
		),
		resetPassword: application.NewResetPasswordUseCase(
			d.userRepo,
			d.recoveryRepo,
			d.tokenSvc,
			d.accountManager,
			infra.txManager,
			d.clock,
			infra.dispatcher,
		),

		// policies
		publicPolicies: application.NewGetPublicPoliciesUseCase(
			domain.PasswordPolicyConfig{
				MinLength:      cfg.PasswordPolicy.MinLength,
				MaxLength:      cfg.PasswordPolicy.MaxLength,
				RequireUpper:   cfg.PasswordPolicy.RequireUpper,
				RequireNumber:  cfg.PasswordPolicy.RequireNumber,
				RequireSpecial: cfg.PasswordPolicy.RequireSpecial,
			},
			domain.RegisterPolicyConfig{
				AllowPublic:    cfg.RegisterPolicy.AllowPublic,
				BlockedDomains: cfg.RegisterPolicy.BlockedDomains,
			},
		),
	}
}
