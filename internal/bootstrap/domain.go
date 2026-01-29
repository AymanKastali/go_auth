package bootstrap

import (
	"go_auth/internal/adapters"
	"go_auth/internal/adapters/persistence/postgres"
	"go_auth/internal/core/application"
	"go_auth/internal/core/domain"

	"gorm.io/gorm"
)

type DomainServices struct {
	IDGen          domain.IIDGenerator
	PasswordSvc    domain.IPasswordService
	UserFactory    domain.IUserFactory
	SessionFactory domain.ISessionFactory
	PasswordPolicy domain.IPasswordPolicy
	RegisterPolicy domain.IRegisterPolicy
	SessionPolicy  domain.ISessionPolicy
	AccessPolicy   domain.IAccessPolicy
	AccessSvc      domain.IAccessService
	Clock          domain.IClock
	TokenSvc       domain.ITokenService

	UserRepo          domain.IUserRepository
	ChangePasswordSvc domain.IChangePassword
	ForgotPasswordSvc domain.IForgotPasswordService
	ResetPasswordSvc  domain.IPasswordResetService
	EmailSvc          application.IEmailService
	TxManager         application.ITransactionManager
}

func NewDomainServices(cfg *adapters.Config, db *gorm.DB) DomainServices {
	//
	uuidGen := adapters.NewUUIDV7Generator()
	passwordSvc := adapters.NewPasswordService(cfg.Password.BcryptCost)
	tokenSvc := adapters.NewTokenService()
	jwtSvc := adapters.NewJWTService(
		cfg.JWT.Secret,
		cfg.JWT.Issuer,
		cfg.JWT.Audience,
	)
	userFactory := domain.NewUserFactory()
	sessionFactory := domain.NewSessionFactory()
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
	accessPolicy := domain.NewAccessPolicy(cfg.JWT.AccessTTL)
	//
	userRepo := postgres.NewPostgresUserRepository(db)
	recoveryRepo := postgres.NewPostgresRecoveryTokenRepository(db)

	clock := adapters.NewClock()

	emailSvc := adapters.NewEmailService(cfg.Email) // Assuming you have a config for this
	txManager := postgres.NewTransactionManager(db)

	recoveryPolicy := domain.NewRecoveryPolicy(cfg.RecoveryPolicy.Lifetime)

	changePasswordSvc := domain.NewChangePassword(userRepo, passwordSvc, passwordPolicy, clock)
	forgotPasswordSvc := domain.NewForgotPasswordService(recoveryRepo, tokenSvc, uuidGen, recoveryPolicy)
	resetPasswordSvc := domain.NewPasswordResetService(userRepo, recoveryRepo, tokenSvc, passwordSvc, passwordPolicy)

	return DomainServices{
		UserRepo:       userRepo,
		PasswordSvc:    passwordSvc,
		UserFactory:    userFactory,
		SessionFactory: sessionFactory,
		PasswordPolicy: passwordPolicy,
		RegisterPolicy: registerPolicy,
		SessionPolicy:  sessionPolicy,
		AccessPolicy:   accessPolicy,
		Clock:          clock,
		AccessSvc:      jwtSvc,
		TokenSvc:       tokenSvc,

		IDGen:             uuidGen,
		ChangePasswordSvc: changePasswordSvc,
		ForgotPasswordSvc: forgotPasswordSvc,
		ResetPasswordSvc:  resetPasswordSvc,
		EmailSvc:          emailSvc,
		TxManager:         txManager,
	}
}
