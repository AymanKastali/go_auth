package main

import (
	"go_auth/internal/adapters"
	"go_auth/internal/adapters/persistence/postgres"
	"go_auth/internal/core/application"
	"go_auth/internal/core/domain"

	"gorm.io/gorm"
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
	emailSvc          application.IEmailService
	txManager         application.ITransactionManager
}

func newDomainServices(cfg *adapters.Config, db *gorm.DB) domainServices {
	idGen := adapters.NewUUIDV7Generator()
	passwordSvc := adapters.NewPasswordService(cfg.Password.BcryptCost)
	tokenSvc := adapters.NewTokenService()
	accessSvc := adapters.NewJWTService(
		cfg.JWT.Secret,
		cfg.JWT.Issuer,
		cfg.JWT.Audience,
	)
	passwordPolicy := domain.NewPasswordPolicy(
		cfg.PasswordPolicy.MinLength,
		cfg.PasswordPolicy.MaxLength,
		cfg.PasswordPolicy.RequireUpper,
		cfg.PasswordPolicy.RequireNumber,
		cfg.PasswordPolicy.RequireSpecial,
	)
	registerPolicy := domain.NewRegisterPolicy(
		cfg.RegisterPolicy.AllowPublic,
		cfg.RegisterPolicy.BlockedDomains,
	)
	sessionPolicy := domain.NewSessionPolicy(
		cfg.SessionPolicy.Lifetime,
		cfg.SessionPolicy.MaxActive,
	)
	userRepo := postgres.NewPostgresUserRepository(db)
	accessPolicy := domain.NewAccessPolicy(cfg.JWT.AccessTTL)
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
	recoveryPolicy := domain.NewRecoveryPolicy(cfg.RecoveryPolicy.Lifetime)
	recoveryRepo := postgres.NewPostgresRecoveryTokenRepository(db)
	accountManager := domain.NewUserAccountManager(
		userRepo,
		recoveryRepo,
		tokenSvc,
		passwordManager,
		idGen,
		recoveryPolicy,
	)

	clock := adapters.NewClock()

	emailSvc := adapters.NewEmailService(cfg.Email)
	txManager := postgres.NewTransactionManager(db)

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
		emailSvc:          emailSvc,
		txManager:         txManager,
		recoveryRepo:      recoveryRepo,
	}
}
