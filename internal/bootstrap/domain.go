package bootstrap

import (
	"go_auth/internal/adapters"
	"go_auth/internal/adapters/persistence/postgres"
	"go_auth/internal/core/application"
	"go_auth/internal/core/domain"

	"gorm.io/gorm"
)

type DomainServices struct {
	IDGen             domain.IIDGenerator
	PasswordManager   domain.IPasswordManager
	RegisterPolicy    domain.IRegisterPolicy
	SessionPolicy     domain.ISessionPolicy
	AccessPolicy      domain.IAccessPolicy
	AccessSvc         domain.IAccessService
	Clock             domain.IClock
	TokenSvc          domain.ITokenService
	RegistrationSvc   domain.IRegistrationService
	AccessManager     domain.IAccessManager
	AuthenticationSvc domain.IAuthenticationService
	AccountManager    domain.IUserAccountManager
	UserRepo          domain.IUserRepository
	RecoveryRepo      domain.IRecoveryTokenRepository
	EmailSvc          application.IEmailService
	TxManager         application.ITransactionManager
}

func NewDomainServices(cfg *adapters.Config, db *gorm.DB) DomainServices {
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

	return DomainServices{
		UserRepo:          userRepo,
		PasswordManager:   passwordManager,
		RegisterPolicy:    registerPolicy,
		SessionPolicy:     sessionPolicy,
		AccessPolicy:      accessPolicy,
		Clock:             clock,
		AccessSvc:         accessSvc,
		TokenSvc:          tokenSvc,
		RegistrationSvc:   registrationSvc,
		AccessManager:     accessManager,
		AuthenticationSvc: authSvc,
		AccountManager:    accountManager,
		IDGen:             idGen,
		EmailSvc:          emailSvc,
		TxManager:         txManager,
		RecoveryRepo:      recoveryRepo,
	}
}
