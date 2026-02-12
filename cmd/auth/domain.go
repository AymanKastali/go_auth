package main

import (
	"go_auth/internal/adapters"
	"go_auth/internal/adapters/outbound"
	"go_auth/internal/adapters/outbound/postgres"
	"go_auth/internal/domain"
)

type domainLayer struct {
	idGen              domain.IIDGenerator
	passwordManager    domain.IPasswordManager
	registerPolicy     domain.IRegisterPolicy
	sessionPolicy      domain.ISessionPolicy
	accessPolicy       domain.IAccessPolicy
	activationPolicy   domain.IActivationPolicy
	accessSvc          domain.IAccessService
	clock              domain.IClock
	tokenSvc           domain.ITokenService
	registrationSvc    domain.IRegistrationService
	accessManager      domain.IAccessManager
	authenticationSvc  domain.IAuthenticationService
	accountManager     domain.IUserAccountManager
	userRepo           domain.IUserRepository
	sessionRepo        domain.ISessionRepository
	recoveryRepo       domain.IRecoveryTokenRepository
	activationRepo     domain.IActivationTokenRepository
	roleRepo           domain.IRoleRepository
}

func newDomainLayer(cfg *adapters.Config, pf *postgres.PersistenceFactory) domainLayer {
	idGen := outbound.NewULIDIDGenerator()
	passwordSvc := outbound.NewPasswordService(cfg.Password.BcryptCost)
	tokenSvc := outbound.NewTokenService()
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
	activationRepo := pf.NewActivationTokenRepository()
	roleProvider := outbound.NewRegistrationRoleProvider(roleRepo)
	registrationSvc := domain.NewRegistrationService(userRepo, roleProvider, registerPolicy, activationPolicy)
	passwordManager := domain.NewPasswordManager(
		passwordSvc,
		passwordPolicy,
	)
	accessManager := domain.NewAccessManager(
		userRepo,
		sessionRepo,
		roleRepo,
		accessSvc,
		accessPolicy,
	)
	authSvc := domain.NewAuthenticationService(
		userRepo,
		sessionRepo,
		tokenSvc,
		idGen,
		sessionPolicy,
		passwordManager,
	)
	recoveryPolicy := domain.NewRecoveryPolicy(domain.RecoveryPolicyConfig{
		Lifetime: cfg.RecoveryPolicy.Lifetime,
	})
	recoveryRepo := pf.NewRecoveryTokenRepository()
	accountManager := domain.NewUserAccountManager(
		tokenSvc,
		passwordManager,
		idGen,
		recoveryPolicy,
		activationPolicy,
	)

	clock := outbound.NewClock()

	return domainLayer{
		userRepo:           userRepo,
		sessionRepo:        sessionRepo,
		passwordManager:    passwordManager,
		registerPolicy:     registerPolicy,
		sessionPolicy:      sessionPolicy,
		accessPolicy:       accessPolicy,
		activationPolicy:   activationPolicy,
		clock:              clock,
		accessSvc:          accessSvc,
		tokenSvc:           tokenSvc,
		registrationSvc:    registrationSvc,
		accessManager:      accessManager,
		authenticationSvc:  authSvc,
		accountManager:     accountManager,
		idGen:              idGen,
		recoveryRepo:       recoveryRepo,
		activationRepo:     activationRepo,
		roleRepo:           roleRepo,
	}
}
