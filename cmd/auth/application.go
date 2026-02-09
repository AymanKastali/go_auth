package main

import (
	"go_auth/internal/adapters"
	"go_auth/internal/application"
	"go_auth/internal/domain"
)

type applicationLayer struct {
	// auth
	seedSA             application.ISeedSuperAdminUseCase
	register           application.IRegisterUseCase
	login              application.ILoginUseCase
	refresh            application.IRefreshTokenUseCase
	logout             application.ILogoutUseCase
	validate           application.IValidateAccessUseCase
	confirmActivation  application.IConfirmActivationUseCase
	resendActivation   application.IResendActivationUseCase

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

	// admin - roles
	listRoles        application.IListRolesUseCase
	getRole          application.IGetRoleUseCase
	createRole       application.ICreateRoleUseCase
	assignPermission application.IAssignPermissionUseCase
	revokePermission application.IRevokePermissionUseCase

	// admin - users
	listUsers       application.IListUsersUseCase
	assignUserRole  application.IAssignUserRoleUseCase
	revokeUserRole  application.IRevokeUserRoleUseCase
	adminActivate   application.IAdminActivateUserUseCase
	adminDeactivate application.IAdminDeactivateUserUseCase
	adminDelete     application.IAdminDeleteUserUseCase
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
			d.accountManager,
			d.activationRepo,
			out.emailSvc,
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
		confirmActivation: application.NewConfirmActivationUseCase(
			d.userRepo,
			d.activationRepo,
			d.tokenSvc,
			d.accountManager,
			out.txManager,
			d.clock,
			out.dispatcher,
		),
		resendActivation: application.NewResendActivationUseCase(
			d.userRepo,
			d.activationRepo,
			d.accountManager,
			out.emailSvc,
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
			cfg.Activation.RequireEmail,
		),

		// admin - roles
		listRoles: application.NewListRolesUseCase(d.roleRepo),
		getRole:   application.NewGetRoleUseCase(d.roleRepo),
		createRole: application.NewCreateRoleUseCase(
			d.roleRepo, d.idGen, d.clock, out.dispatcher,
		),
		assignPermission: application.NewAssignPermissionUseCase(
			d.roleRepo, d.clock, out.dispatcher,
		),
		revokePermission: application.NewRevokePermissionUseCase(
			d.roleRepo, d.clock, out.dispatcher,
		),

		// admin - users
		listUsers: application.NewListUsersUseCase(out.userQuery),
		assignUserRole: application.NewAssignUserRoleUseCase(
			d.userRepo, d.roleRepo, d.clock, out.dispatcher,
		),
		revokeUserRole: application.NewRevokeUserRoleUseCase(
			d.userRepo, d.clock, out.dispatcher,
		),
		adminActivate: application.NewAdminActivateUserUseCase(
			d.userRepo, d.clock, out.dispatcher,
		),
		adminDeactivate: application.NewAdminDeactivateUserUseCase(
			d.userRepo, d.clock, out.dispatcher,
		),
		adminDelete: application.NewAdminDeleteUserUseCase(
			d.userRepo, d.sessionRepo, d.clock, out.dispatcher,
		),
	}
}
