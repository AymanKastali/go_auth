package main

import (
	"go_auth/internal/adapters"
	"go_auth/internal/application/command"
	"go_auth/internal/application/query"
	"go_auth/internal/domain"
)

type applicationLayer struct {
	// auth
	seedSA            command.ISeedSuperAdminHandler
	register          command.IRegisterHandler
	login             command.ILoginHandler
	refresh           command.IRefreshTokenHandler
	logout            command.ILogoutHandler
	validate          query.IValidateAccessHandler
	confirmActivation command.IConfirmActivationHandler
	resendActivation  command.IResendActivationHandler

	// user
	findByEmail    query.IFindUserByEmailHandler
	getByID        query.IGetUserByIDHandler
	getMe          query.IGetMeHandler
	updateMe       command.IUpdateMeHandler
	changePassword command.IChangePasswordHandler
	forgotPassword command.IForgotPasswordHandler
	resetPassword  command.IResetPasswordHandler

	// seeding
	seedRoles command.ISeedRolesHandler

	// policies
	publicPolicies query.IGetPublicPoliciesHandler

	// admin - roles
	listRoles        query.IListRolesHandler
	getRole          query.IGetRoleHandler
	createRole       command.ICreateRoleHandler
	assignPermission command.IAssignPermissionHandler
	revokePermission command.IRevokePermissionHandler

	// admin - users
	listUsers       query.IListUsersHandler
	assignUserRole  command.IAssignUserRoleHandler
	revokeUserRole  command.IRevokeUserRoleHandler
	adminActivate   command.IAdminActivateUserHandler
	adminDeactivate command.IAdminDeactivateUserHandler
	adminDelete     command.IAdminDeleteUserHandler
}

func newApplicationLayer(d domainLayer, out outboundAdapters, cfg *adapters.Config) applicationLayer {
	return applicationLayer{
		register: command.NewRegisterHandler(
			d.userRepo,
			d.registerMember,
			d.passwordPolicy,
			d.passwordSvc,
			d.idGen,
			d.clock,
			out.dispatcher,
			d.initiateActivation,
			d.activationRepo,
			out.emailSvc,
		),
		seedSA: command.NewSeedSuperAdminHandler(
			d.userRepo,
			d.registerAdmin,
			d.passwordPolicy,
			d.passwordSvc,
			d.idGen,
			d.clock,
			out.dispatcher,
		),
		login: command.NewLoginHandler(
			d.userRepo,
			d.sessionRepo,
			d.verifyCredentials,
			d.openSession,
			d.grantAccess,
			d.clock,
			out.dispatcher,
		),
		refresh: command.NewRefreshTokenHandler(
			d.sessionRepo,
			d.refreshSession,
			d.grantAccess,
			d.clock,
			out.dispatcher,
		),
		validate: query.NewValidateAccessHandler(
			d.verifyAccess,
			d.resolvePermissions,
			d.clock,
		),
		logout: command.NewLogoutHandler(
			d.sessionRepo, d.clock, out.dispatcher,
		),

		// user
		findByEmail: query.NewFindUserByEmailHandler(out.userQuery),
		getByID:     query.NewGetUserByIDHandler(out.userQuery),
		getMe:       query.NewGetMeHandler(out.userQuery),
		updateMe:    command.NewUpdateMeHandler(d.userRepo, d.clock, out.dispatcher),
		forgotPassword: command.NewForgotPasswordHandler(
			d.userRepo,
			d.recoveryRepo,
			d.initiateRecovery,
			out.emailSvc,
			out.txManager,
			d.clock,
			out.dispatcher,
		),
		changePassword: command.NewChangePasswordHandler(
			d.userRepo,
			d.sessionRepo,
			d.passwordPolicy,
			d.changePassword,
			d.clock,
			out.dispatcher,
		),
		resetPassword: command.NewResetPasswordHandler(
			d.userRepo,
			d.sessionRepo,
			d.recoveryRepo,
			d.tokenSvc,
			d.passwordPolicy,
			d.resetPassword,
			out.txManager,
			d.clock,
			out.dispatcher,
		),
		confirmActivation: command.NewConfirmActivationHandler(
			d.userRepo,
			d.activationRepo,
			d.tokenSvc,
			d.confirmActivation,
			out.txManager,
			d.clock,
			out.dispatcher,
		),
		resendActivation: command.NewResendActivationHandler(
			d.userRepo,
			d.activationRepo,
			d.initiateActivation,
			out.emailSvc,
			out.txManager,
			d.clock,
			out.dispatcher,
		),

		// seeding
		seedRoles: command.NewSeedRolesHandler(
			d.roleRepo,
			d.idGen,
			d.clock,
			out.dispatcher,
			out.seedLoader,
		),

		// policies
		publicPolicies: query.NewGetPublicPoliciesHandler(
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
		listRoles: query.NewListRolesHandler(out.roleQuery),
		getRole:   query.NewGetRoleHandler(out.roleQuery),
		createRole: command.NewCreateRoleHandler(
			d.roleRepo, d.idGen, d.clock, out.dispatcher,
		),
		assignPermission: command.NewAssignPermissionHandler(
			d.roleRepo, d.clock, out.dispatcher,
		),
		revokePermission: command.NewRevokePermissionHandler(
			d.roleRepo, d.clock, out.dispatcher,
		),

		// admin - users
		listUsers: query.NewListUsersHandler(out.userQuery),
		assignUserRole: command.NewAssignUserRoleHandler(
			d.userRepo, d.roleRepo, d.clock, out.dispatcher,
		),
		revokeUserRole: command.NewRevokeUserRoleHandler(
			d.userRepo, d.clock, out.dispatcher,
		),
		adminActivate: command.NewAdminActivateUserHandler(
			d.userRepo, d.clock, out.dispatcher,
		),
		adminDeactivate: command.NewAdminDeactivateUserHandler(
			d.userRepo, d.clock, out.dispatcher,
		),
		adminDelete: command.NewAdminDeleteUserHandler(
			d.userRepo, d.sessionRepo, d.clock, out.dispatcher,
		),
	}
}
