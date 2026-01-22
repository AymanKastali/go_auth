package fiber

import (
	"go_auth/config"
	"go_auth/internal/adapters/http/fiber/api/v1/handlers/auth"
	"go_auth/internal/adapters/http/fiber/api/v1/handlers/roles"
	"go_auth/internal/adapters/http/fiber/api/v1/handlers/users"
	"go_auth/internal/adapters/http/fiber/middlewares"
	"go_auth/internal/adapters/persistence/postgres/mappers"
	"go_auth/internal/adapters/persistence/postgres/repositories"
	adaptersvc "go_auth/internal/adapters/services"
	"go_auth/internal/core/application/services"
	"go_auth/internal/core/application/usecases"
	"go_auth/internal/core/domain/factories"
	"go_auth/internal/core/domain/policies"
	domainsvc "go_auth/internal/core/domain/services"
	"log/slog"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

type Deps struct {
	RegisterHandler     *auth.RegisterHandler
	LoginHandler        *auth.LoginHandler
	RefreshTokenHandler *auth.RefreshTokenHandler
	LogoutHandler       *auth.LogoutHandler
	UpdateRoleHandler   *roles.UpdateRoleHandler
	AuthUserHandler     *users.AuthUserHandler
	AuthMiddleware      fiber.Handler
	Logger              *slog.Logger
}

func InitDeps(db *gorm.DB, cfg *config.Config, logger *slog.Logger) (*Deps, error) {
	// =========================
	// Infrastructure Services
	// =========================
	clockSvc := adaptersvc.NewClockSvc()
	idSvc := adaptersvc.NewUUIDSvc()

	pwdHasher := adaptersvc.NewBcryptHasher(cfg.Security.BcryptCost)
	tokenHasher := adaptersvc.NewHMACHasher(cfg.Security.HMACSecret)
	tokenGenerator := adaptersvc.NewCryptoRandomTokenGenerator(cfg.Security.RefreshTokenSecretBytes)

	jwtIssuer := adaptersvc.NewJWTSessionTokenIssuerService(
		cfg.JWT.PrivateKey,
		cfg.JWT.PublicKey,
		cfg.JWT.Issuer,
		cfg.JWT.Audience,
	)

	// =========================
	// Repositories
	// =========================
	userRepo := repositories.NewGormUserRepository(db, mappers.NewUserMapper(), idSvc, pwdHasher)
	roleRepo := repositories.NewGormRoleRepository(db, mappers.NewRoleMapper(), idSvc)
	deviceRepo := repositories.NewGormDeviceRepository(db, mappers.NewDeviceMapper(), idSvc)
	refreshRepo := repositories.NewGormRefreshTokenRepository(db, mappers.NewRefreshTokenMapper())

	// =========================
	// Policies
	// =========================
	jwtPolicy := policies.NewDefaultJWTPolicy()
	refreshTokenPolicy := policies.NewDefaultRefreshTokenPolicy()
	passwordPolicy := policies.NewDefaultPasswordPolicy()

	// =========================
	// Domain Factories
	// =========================
	deviceFactory := factories.NewDefaultDeviceFactory(idSvc, clockSvc)
	refreshTokenFactory := factories.NewDefaultRefreshTokenFactory(
		tokenGenerator,
		tokenHasher,
		idSvc,
		refreshTokenPolicy,
	)
	registrationPolicy := domainsvc.NewDefaultUserRegistrationPolicy(userRepo, roleRepo)
	userFactory := factories.NewDefaultUserFactory(registrationPolicy, passwordPolicy, idSvc, pwdHasher)

	// =========================
	// Domain Services
	// =========================
	authDomainSvc := domainsvc.NewAuthDomainService(userRepo, deviceRepo, pwdHasher, idSvc, deviceFactory)
	sessionDomainSvc := domainsvc.NewSessionDomainService(refreshRepo, refreshTokenFactory)

	// =========================
	// Application Use Cases
	// =========================
	registerUC := usecases.NewRegisterUseCase(userRepo, userFactory, clockSvc)

	loginUC := usecases.NewLoginUseCase(
		authDomainSvc,
		refreshRepo,
		roleRepo,
		jwtIssuer,
		idSvc,
		clockSvc,
		sessionDomainSvc,
		jwtPolicy,
	)

	refreshUC := usecases.NewRefreshTokenUseCase(
		sessionDomainSvc,
		refreshRepo,
		userRepo,
		roleRepo,
		deviceRepo,
		jwtIssuer,
		clockSvc,
		idSvc,
		tokenHasher,
		jwtPolicy,
	)

	logoutUC := usecases.NewLogoutUseCase(refreshRepo, clockSvc, tokenHasher)
	authUserUC := usecases.NewAuthUserUseCase(userRepo, roleRepo)
	roleUC := usecases.NewUpdateRoleUseCase(userRepo, roleRepo, idSvc, clockSvc)

	// =========================
	// Seeders
	// =========================
	if err := services.NewSeedRolesSvc(roleRepo, idSvc, clockSvc, logger).SeedDefaultRoles(); err != nil {
		return nil, err
	}

	if err := services.NewSeedAdminSvc(
		userRepo,
		roleRepo,
		pwdHasher,
		idSvc,
		clockSvc,
		cfg.AdminSeeder.AdminEmail,
		cfg.AdminSeeder.AdminPassword,
		logger,
	).SeedAdmin(); err != nil {
		return nil, err
	}

	// =========================
	// HTTP Handlers & Middleware
	// =========================
	deps := &Deps{
		RegisterHandler:     auth.NewRegisterHandler(registerUC),
		LoginHandler:        auth.NewLoginHandler(loginUC),
		RefreshTokenHandler: auth.NewRefreshTokenHandler(refreshUC),
		LogoutHandler:       auth.NewLogoutHandler(logoutUC),
		UpdateRoleHandler:   roles.NewUpdateRoleHandler(roleUC),
		AuthUserHandler:     users.NewAuthUserHandler(authUserUC),

		AuthMiddleware: middlewares.JWTMiddleware(jwtIssuer, deviceRepo, idSvc),
		Logger:         logger,
	}

	return deps, nil
}
