package bootstrap

import (
	"go_auth/internal/adapters"
	"go_auth/internal/adapters/persistence/postgres"
	"go_auth/internal/core/domain"

	"gorm.io/gorm"
)

type DomainServices struct {
	UserRepo      domain.IUserRepository
	RegisterSvc   domain.IRegisterUserService
	AuthSvc       domain.IAuthenticateUser
	SessionSvc    domain.IEstablishUserSession
	RefreshSvc    domain.IRefreshSession
	AccessGrantor domain.IAccessGrantor
	AccessSvc     domain.IAccessTokenService
	Clock         domain.IClock
	ULIDGen       domain.IIDGenerator
}

func SetupDomain(cfg *adapters.Config, db *gorm.DB) DomainServices {
	userRepo := postgres.NewPostgresUserRepository(db)

	clock := adapters.NewClock()
	uuidGen := adapters.NewUUIDV7Generator()
	ulidGen := adapters.NewULIDGenerator()
	passwordSvc := adapters.NewPasswordService(cfg.Password.BcryptCost)
	jwtSvc := adapters.NewJWTService(cfg.JWT.Secret, cfg.JWT.Issuer, cfg.JWT.Audience)
	tokenSvc := adapters.NewTokenService()

	passPolicy := domain.NewPasswordPolicy(
		cfg.PasswordPolicy.MinLength,
		cfg.PasswordPolicy.MaxLength,
		cfg.PasswordPolicy.RequireUpper,
		cfg.PasswordPolicy.RequireNumber,
		cfg.PasswordPolicy.RequireSpecial,
	)

	sessionPolicy := domain.NewSessionPolicy(cfg.SessionPolicy.Lifetime, cfg.SessionPolicy.MaxActive)
	accessPolicy := domain.NewAccessPolicy(cfg.JWT.AccessTTL)

	userFactory := domain.NewUserFactory()
	sessionFactory := domain.NewSessionFactory()

	registerSvc := domain.NewRegisterUserService(userRepo, passPolicy, passwordSvc, userFactory, uuidGen, clock)
	authSvc := domain.NewAuthenticateUserService(userRepo, passwordSvc)
	sessionSvc := domain.NewEstablishUserSessionService(sessionFactory, sessionPolicy, clock, uuidGen, tokenSvc)
	refreshSvc := domain.NewRefreshSessionService(userRepo, tokenSvc, clock)
	accessGrantor := domain.NewAccessGrantor(jwtSvc, accessPolicy, clock)

	return DomainServices{
		UserRepo:      userRepo,
		RegisterSvc:   registerSvc,
		AuthSvc:       authSvc,
		SessionSvc:    sessionSvc,
		RefreshSvc:    refreshSvc,
		AccessGrantor: accessGrantor,
		AccessSvc:     jwtSvc,
		Clock:         clock,
		ULIDGen:       ulidGen,
	}
}
