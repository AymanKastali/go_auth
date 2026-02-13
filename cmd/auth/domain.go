package main

import (
	"go_auth/internal/adapters"
	"go_auth/internal/adapters/outbound"
	"go_auth/internal/adapters/outbound/postgres"
	"go_auth/internal/domain"
)

type domainLayer struct {
	idGen              domain.IIDGenerator
	passwordPolicy     domain.IPasswordPolicy
	registerPolicy     domain.IRegisterPolicy
	sessionPolicy      domain.ISessionPolicy
	accessPolicy       domain.IAccessPolicy
	activationPolicy   domain.IActivationPolicy
	loginPolicy        domain.ILoginPolicy
	accessSvc          domain.IAccessService
	passwordSvc        domain.IPasswordService
	clock              domain.IClock
	tokenSvc           domain.ITokenService
	registerMember     domain.IRegisterMember
	registerAdmin      domain.IRegisterAdmin
	grantAccess        domain.IGrantAccess
	resolvePermissions domain.IResolvePermissions
	verifyCredentials  domain.IVerifyCredentials
	openSession        domain.IOpenSession
	refreshSession     domain.IRefreshSession
	initiateRecovery   domain.IInitiateRecovery
	changePassword     domain.IChangePassword
	resetPassword      domain.IResetPassword
	initiateActivation domain.IInitiateActivation
	confirmActivation  domain.IConfirmActivation
	userRepo           domain.IUserRepository
	sessionRepo        domain.ISessionRepository
	recoveryRepo       domain.IRecoveryTokenRepository
	activationRepo     domain.IActivationTokenRepository
	roleRepo           domain.IRoleRepository
	roleProvider       domain.IRegistrationRoleProvider
}

func newDomainLayer(cfg *adapters.Config, pf *postgres.PersistenceFactory) domainLayer {
	idGen := outbound.NewULIDIdGenerator()
	passwordSvc := outbound.NewPasswordService(cfg.Password.BcryptCost)
	tokenSvc := outbound.NewTokenService(cfg.Token.Length)
	accessSvc := outbound.NewJWTService(
		cfg.JWT.Secret,
		cfg.JWT.Issuer,
		cfg.JWT.Audience,
	)
	passwordPolicy := domain.NewPasswordPolicy(domain.PasswordPolicyConfig{
		MinLength:      cfg.PasswordPolicy.MinLength,
		MaxLength:      cfg.PasswordPolicy.MaxLength,
		RequireUpper:   cfg.PasswordPolicy.RequireUpper,
		RequireNumber:  cfg.PasswordPolicy.RequireNumber,
		RequireSpecial: cfg.PasswordPolicy.RequireSpecial,
	})
	registerPolicy := domain.NewRegisterPolicy(domain.RegisterPolicyConfig{
		AllowPublic:    cfg.RegisterPolicy.AllowPublic,
		BlockedDomains: cfg.RegisterPolicy.BlockedDomains,
	})
	sessionPolicy := domain.NewSessionPolicy(domain.SessionPolicyConfig{
		Lifetime:  cfg.SessionPolicy.Lifetime,
		MaxActive: cfg.SessionPolicy.MaxActive,
	})
	userRepo := pf.NewUserRepository()
	sessionRepo := pf.NewSessionRepository()
	roleRepo := pf.NewRoleRepository()
	accessPolicy := domain.NewAccessPolicy(domain.AccessPolicyConfig{
		Lifetime: cfg.JWT.AccessTTL,
	})
	activationPolicy := domain.NewActivationPolicy(domain.ActivationPolicyConfig{
		RequireEmail:  cfg.Activation.RequireEmail,
		TokenLifetime: cfg.Activation.TokenLifetime,
	})
	loginPolicy := domain.NewLoginPolicy(domain.LoginPolicyConfig{
		MaxAttempts:     cfg.LoginPolicy.MaxAttempts,
		LockoutDuration: cfg.LoginPolicy.LockoutDuration,
	})
	activationRepo := pf.NewActivationTokenRepository()
	roleProvider := outbound.NewRegistrationRoleProvider(roleRepo)
	registerMember := domain.NewRegisterMember(registerPolicy, activationPolicy)
	registerAdmin := domain.NewRegisterAdmin(registerPolicy)
	resolvePermissions := domain.NewResolvePermissions()
	grantAccess := domain.NewGrantAccess(resolvePermissions, accessSvc, accessPolicy)
	verifyCredentials := domain.NewVerifyCredentials(passwordSvc)
	openSession := domain.NewOpenSession(tokenSvc, idGen, sessionPolicy)
	refreshSession := domain.NewRefreshSession(tokenSvc, sessionPolicy)
	recoveryPolicy := domain.NewRecoveryPolicy(domain.RecoveryPolicyConfig{
		Lifetime: cfg.RecoveryPolicy.Lifetime,
	})
	recoveryRepo := pf.NewRecoveryTokenRepository()
	initiateRecovery := domain.NewInitiateRecovery(tokenSvc, idGen, recoveryPolicy)
	changePassword := domain.NewChangePassword(passwordSvc)
	resetPassword := domain.NewResetPassword(passwordSvc)
	initiateActivation := domain.NewInitiateActivation(tokenSvc, idGen, activationPolicy)
	confirmActivation := domain.NewConfirmActivation()

	clock := outbound.NewClock()

	return domainLayer{
		loginPolicy:        loginPolicy,
		userRepo:           userRepo,
		sessionRepo:        sessionRepo,
		passwordPolicy:     passwordPolicy,
		passwordSvc:        passwordSvc,
		registerPolicy:     registerPolicy,
		sessionPolicy:      sessionPolicy,
		accessPolicy:       accessPolicy,
		activationPolicy:   activationPolicy,
		clock:              clock,
		accessSvc:          accessSvc,
		tokenSvc:           tokenSvc,
		registerMember:     registerMember,
		registerAdmin:      registerAdmin,
		grantAccess:        grantAccess,
		resolvePermissions: resolvePermissions,
		verifyCredentials:  verifyCredentials,
		openSession:        openSession,
		refreshSession:     refreshSession,
		initiateRecovery:   initiateRecovery,
		changePassword:     changePassword,
		resetPassword:      resetPassword,
		initiateActivation: initiateActivation,
		confirmActivation:  confirmActivation,
		idGen:              idGen,
		recoveryRepo:       recoveryRepo,
		activationRepo:     activationRepo,
		roleRepo:           roleRepo,
		roleProvider:       roleProvider,
	}
}
