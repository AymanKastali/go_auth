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
	"go_auth/internal/core/application/usecases"
	"go_auth/internal/core/domain/factories"
	"go_auth/internal/core/domain/policies"
	"go_auth/internal/core/domain/services"
	"log/slog"

	"github.com/gofiber/fiber/v3"
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
	deviceHasher := adaptersvc.NewDeviceHasher(string(cfg.Security.RSASecret))
	tokenGenerator := adaptersvc.NewCryptoRandomTokenGenerator(cfg.Security.SessionRenewalRawTokenSecretBytes)

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
	sessionRenewalRepo := repositories.NewGormSessionRenewalTokenRepository(db, mappers.NewSessionRenewalTokenMapper())

	// =========================
	// Policies
	// =========================
	SessionTokenPolicy := policies.NewSessionTokenPolicy()
	sessionRenewalTokenPolicy := policies.NewSessionRenewalTokenPolicy()
	passwordPolicy := policies.NewPasswordPolicy()

	// =========================
	// Domain Factories
	// =========================
	deviceFactory := factories.NewDeviceFactory(idSvc)
	sessionRenewalTokenFactory := factories.NewSessionRenewalTokenFactory(
		idSvc,
		sessionRenewalTokenPolicy,
	)
	userFactory := factories.NewDefaultUserFactory(idSvc)

	// =========================
	// Domain Services
	// =========================
	roleSvc := services.NewRoleService(roleRepo, idSvc)
	userSvc := services.NewUserService(userRepo, roleRepo, pwdHasher, userFactory, passwordPolicy)
	authDomainSvc := services.NewAuthDomainService(userRepo, deviceRepo, pwdHasher, idSvc, deviceFactory, deviceHasher)
	sessionDomainSvc := services.NewSessionDomainSvc(sessionRenewalRepo, sessionRenewalTokenFactory, tokenHasher, tokenGenerator)

	// =========================
	// Application Use Cases
	// =========================
	registerUC := usecases.NewRegisterUseCase(userRepo, userSvc, clockSvc)

	loginUC := usecases.NewLoginUseCase(
		authDomainSvc,
		sessionRenewalRepo,
		roleRepo,
		jwtIssuer,
		idSvc,
		clockSvc,
		sessionDomainSvc,
		SessionTokenPolicy,
	)

	refreshUC := usecases.NewSessionRenewalTokenUseCase(
		authDomainSvc,
		sessionDomainSvc,
		sessionRenewalRepo,
		userRepo,
		roleRepo,
		deviceRepo,
		jwtIssuer,
		clockSvc,
		idSvc,
		SessionTokenPolicy,
	)

	logoutUC := usecases.NewLogoutUseCase(sessionRenewalRepo, sessionDomainSvc, clockSvc)
	authUserUC := usecases.NewAuthUserUseCase(userRepo, roleRepo)
	roleUC := usecases.NewUpdateRoleUseCase(userSvc, userRepo, clockSvc)

	adminUserSeederUC := usecases.NewSeedAdminUseCase(
		userRepo,
		userSvc,
		clockSvc,
	)

	rolesSeederUC := usecases.NewSeedRolesUseCase(roleSvc, roleRepo, clockSvc)

	// =========================
	// Seeders
	// =========================
	if err := rolesSeederUC.Execute(logger); err != nil {
		return nil, err
	}

	if err := adminUserSeederUC.Execute(logger, cfg.AdminSeeder.AdminEmail, cfg.AdminSeeder.AdminPassword); err != nil {
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
