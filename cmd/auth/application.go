package main

import (
	"go_auth/internal/adapters"
	"go_auth/internal/application"
	"go_auth/internal/domain"
)

type applicationLayer struct {
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

	// seeding
	seedRoles application.ISeedRolesUseCase

	// policies
	publicPolicies application.IGetPublicPoliciesUseCase
}

func newApplicationLayer(d domainLayer, out outboundAdapters, cfg *adapters.Config) applicationLayer {
	return applicationLayer{
		register: application.NewRegisterUseCase(
			d.userRepo,
			d.registrationSvc,
			d.passwordManager,
			d.idGen,
			d.clock,
			out.dispatcher,
		),
		seedSA: application.NewSeedSuperAdminUseCase(
			d.userRepo,
			d.registrationSvc,
			d.passwordManager,
			d.idGen,
			d.clock,
			out.dispatcher,
		),
		login: application.NewLoginUseCase(
			d.userRepo,
			d.sessionRepo,
			d.authenticationSvc,
			d.accessManager,
			d.clock,
			out.dispatcher,
		),
		refresh: application.NewRefreshTokenUseCase(
			d.userRepo,
			d.sessionRepo,
			d.authenticationSvc,
			d.accessManager,
			d.clock,
			out.dispatcher,
		),
		validate: application.NewValidateAccessUseCase(
			d.accessManager,
			d.clock,
		),
		logout: application.NewLogoutUseCase(
			d.sessionRepo, d.clock, out.dispatcher,
		),

		// user
		findByEmail: application.NewFindUserByEmailUseCase(out.userQuery),
		getByID:     application.NewGetUserByIDUseCase(out.userQuery),
		getMe:       application.NewGetMeUseCase(out.userQuery),
		updateMe:    application.NewUpdateMeUseCase(d.userRepo, d.clock, out.dispatcher),
		forgotPassword: application.NewForgotPasswordUseCase(
			d.userRepo,
			d.recoveryRepo,
			d.accountManager,
			out.emailSvc,
			out.txManager,
			d.clock,
			out.dispatcher,
		),
		changePassword: application.NewChangePasswordUseCase(
			d.userRepo,
			d.sessionRepo,
			d.accountManager,
			d.clock,
			out.dispatcher,
		),
		resetPassword: application.NewResetPasswordUseCase(
			d.userRepo,
			d.sessionRepo,
			d.recoveryRepo,
			d.tokenSvc,
			d.accountManager,
			out.txManager,
			d.clock,
			out.dispatcher,
		),

		// seeding
		seedRoles: application.NewSeedRolesUseCase(
			d.roleRepo,
			d.idGen,
			d.clock,
			out.dispatcher,
			out.seedLoader,
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
