package main

import (
	"go_auth/internal/adapters"
	"go_auth/internal/adapters/persistence/postgres"
	"go_auth/internal/core/domain"
)

type domainServices struct {
	idGen             domain.IIDGenerator
	passwordManager   domain.IPasswordManager
	registerPolicy    domain.IRegisterPolicy
	sessionPolicy     domain.ISessionPolicy
	accessPolicy      domain.IAccessPolicy
	accessSvc         domain.IAccessService
	clock             domain.IClock
	tokenSvc          domain.ITokenService
	registrationSvc   domain.IRegistrationService
	accessManager     domain.IAccessManager
	authenticationSvc domain.IAuthenticationService
	accountManager    domain.IUserAccountManager
	userRepo          domain.IUserRepository
	recoveryRepo      domain.IRecoveryTokenRepository
}

func newDomainServices(cfg *adapters.Config, pf *postgres.PersistenceFactory) domainServices {
	idGen := adapters.NewUUIDV7Generator()
	passwordSvc := adapters.NewPasswordService(cfg.Password.BcryptCost)
	tokenSvc := adapters.NewTokenService()
	accessSvc := adapters.NewJWTService(
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
	accessPolicy := domain.NewAccessPolicy(domain.AccessPolicyConfig{
		Lifetime: cfg.JWT.AccessTTL,
	})
	registrationSvc := domain.NewRegistrationService(userRepo, registerPolicy)
	passwordManager := domain.NewPasswordManager(
		passwordSvc,
		passwordPolicy,
	)
	accessManager := domain.NewAccessManager(
		userRepo,
		accessSvc,
		accessPolicy,
	)
	authSvc := domain.NewAuthenticationService(
		userRepo,
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
	)

	clock := adapters.NewClock()

	return domainServices{
		userRepo:          userRepo,
		passwordManager:   passwordManager,
		registerPolicy:    registerPolicy,
		sessionPolicy:     sessionPolicy,
		accessPolicy:      accessPolicy,
		clock:             clock,
		accessSvc:         accessSvc,
		tokenSvc:          tokenSvc,
		registrationSvc:   registrationSvc,
		accessManager:     accessManager,
		authenticationSvc: authSvc,
		accountManager:    accountManager,
		idGen:             idGen,
		recoveryRepo:      recoveryRepo,
	}
}
