package bootstrap

import (
	"go_auth/internal/adapters"
	"go_auth/internal/adapters/persistence/postgres"
	"go_auth/internal/core/application"
	"go_auth/internal/core/domain"

	"gorm.io/gorm"
)

type DomainServices struct {
	UserRepo          domain.IUserRepository
	RegisterSvc       domain.IRegisterUserService
	AuthSvc           domain.IAuthenticateUser
	SessionSvc        domain.IEstablishUserSession
	RefreshSvc        domain.IRefreshSession
	AccessGrantor     domain.IAccessGrantor
	AccessSvc         domain.IAccessTokenService
	Clock             domain.IClock
	IDGen             domain.IIDGenerator
	ChangePasswordSvc domain.IChangePassword
	ForgotPasswordSvc domain.IForgotPasswordService
	ResetPasswordSvc  domain.IPasswordResetService
	EmailSvc          application.IEmailService
	TxManager         application.ITransactionManager
}

func NewDomainServices(cfg *adapters.Config, db *gorm.DB) DomainServices {
	userRepo := postgres.NewPostgresUserRepository(db)
	recoveryRepo := postgres.NewPostgresRecoveryTokenRepository(db)

	clock := adapters.NewClock()
	uuidGen := adapters.NewUUIDV7Generator()
	passwordSvc := adapters.NewPasswordService(cfg.Password.BcryptCost)
	jwtSvc := adapters.NewJWTService(cfg.JWT.Secret, cfg.JWT.Issuer, cfg.JWT.Audience)
	tokenSvc := adapters.NewTokenService()

	emailSvc := adapters.NewEmailService(cfg.Email) // Assuming you have a config for this
	txManager := postgres.NewTransactionManager(db)

	passPolicy := domain.NewPasswordPolicy(
		cfg.PasswordPolicy.MinLength,
		cfg.PasswordPolicy.MaxLength,
		cfg.PasswordPolicy.RequireUpper,
		cfg.PasswordPolicy.RequireNumber,
		cfg.PasswordPolicy.RequireSpecial,
	)

	sessionPolicy := domain.NewSessionPolicy(cfg.SessionPolicy.Lifetime, cfg.SessionPolicy.MaxActive)
	accessPolicy := domain.NewAccessPolicy(cfg.JWT.AccessTTL)
	recoveryPolicy := domain.NewRecoveryPolicy(cfg.RecoveryPolicy.Lifetime)

	userFactory := domain.NewUserFactory()
	sessionFactory := domain.NewSessionFactory()

	registerSvc := domain.NewRegisterUserService(userRepo, passPolicy, passwordSvc, userFactory, uuidGen, clock)
	authSvc := domain.NewAuthenticateUserService(userRepo, passwordSvc)
	sessionSvc := domain.NewEstablishUserSessionService(sessionFactory, sessionPolicy, clock, uuidGen, tokenSvc)
	refreshSvc := domain.NewRefreshSessionService(userRepo, tokenSvc, clock)
	accessGrantor := domain.NewAccessGrantor(jwtSvc, accessPolicy, clock)
	changePasswordSvc := domain.NewChangePassword(userRepo, passwordSvc, passPolicy, clock)
	forgotPasswordSvc := domain.NewForgotPasswordService(recoveryRepo, tokenSvc, uuidGen, recoveryPolicy)
	resetPasswordSvc := domain.NewPasswordResetService(userRepo, recoveryRepo, tokenSvc, passwordSvc, passPolicy)

	return DomainServices{
		UserRepo:          userRepo,
		RegisterSvc:       registerSvc,
		AuthSvc:           authSvc,
		SessionSvc:        sessionSvc,
		RefreshSvc:        refreshSvc,
		AccessGrantor:     accessGrantor,
		AccessSvc:         jwtSvc,
		Clock:             clock,
		IDGen:             uuidGen,
		ChangePasswordSvc: changePasswordSvc,
		ForgotPasswordSvc: forgotPasswordSvc,
		ResetPasswordSvc:  resetPasswordSvc,
		EmailSvc:          emailSvc,
		TxManager:         txManager,
	}
}
