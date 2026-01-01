package bootstrap

import (
	"go_auth/internal/adapters/config"
	auth_handlers "go_auth/internal/adapters/http/fiber/api/v1/handlers/auth"
	user_handlers "go_auth/internal/adapters/http/fiber/api/v1/handlers/user"
	"go_auth/internal/adapters/http/fiber/middlewares"
	"go_auth/internal/adapters/mappers"
	"go_auth/internal/adapters/persistence/postgres/repositories"
	"go_auth/internal/adapters/security/jwt"
	"go_auth/internal/adapters/security/password"
	"go_auth/internal/core/application/services"
	"go_auth/internal/core/application/use_cases"
	"log"
	"log/slog"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

type deps struct {
	registerHandler     *auth_handlers.RegisterHandler
	loginHandler        *auth_handlers.LoginHandler
	refreshTokenHandler *auth_handlers.RefreshTokenHandler
	logoutHandler       *auth_handlers.LogoutHandler
	roleHandler         *auth_handlers.RoleHandler
	authUserHandler     *user_handlers.AuthenticatedUserHandler
	AuthMiddleware      fiber.Handler
	Logger              *slog.Logger
}

func wireDependencies(
	db *gorm.DB,
) (*deps, error) {
	// infra
	userMapper := mappers.NewUserMapper()
	deviceMapper := mappers.NewDeviceMapper()
	refreshTokenMapper := mappers.NewRefreshTokenMapper()

	userRepo := repositories.NewGormUserRepository(db, userMapper)
	refreshTokenRepo := repositories.NewGormRefreshTokenRepository(db, refreshTokenMapper)
	deviceRepo := repositories.NewGormDeviceRepository(db, deviceMapper)

	passwordHasher := password.NewBcryptHashedPassworder(12)

	jwtCfg, err := config.LoadJWTConfigFromEnv()
	if err != nil {
		return nil, err
	}
	jwtService := jwt.NewJWTService(jwtCfg)

	seederCfg, err := config.LoadSeederConfig()
	if err != nil {
		return nil, err
	}

	// logger
	logger := initLogger()

	seeder := services.NewSeedAdminService(
		userRepo,
		passwordHasher,
		seederCfg,
		logger,
	)

	if err := seeder.SeedAdmin(); err != nil {
		log.Fatal(err)
	}

	// handlers
	registerUc := use_cases.NewRegisterUseCase(
		userRepo,
		passwordHasher,
		logger,
	)

	loginUc := use_cases.NewLoginUseCase(
		userRepo,
		refreshTokenRepo,
		deviceRepo,
		passwordHasher,
		jwtService,
		logger,
	)

	logoutUc := use_cases.NewLogoutUseCase(
		refreshTokenRepo,
		jwtService,
		logger,
	)

	refreshTokenUc := use_cases.NewRefreshTokenUseCase(
		userRepo,
		refreshTokenRepo,
		deviceRepo,
		jwtService,
		logger,
	)

	getAuthUserUc := use_cases.NewAuthenticatedUserUseCase(
		userRepo,
		logger,
	)

	manageRoleUc := use_cases.NewManageRoleUseCase(
		userRepo,
		logger,
	)

	return &deps{
		registerHandler:     auth_handlers.NewRegisterHandler(registerUc),
		loginHandler:        auth_handlers.NewLoginHandler(loginUc),
		logoutHandler:       auth_handlers.NewLogoutHandler(logoutUc),
		refreshTokenHandler: auth_handlers.NewRefreshTokenHandler(refreshTokenUc),
		roleHandler:         auth_handlers.NewRoleHandler(manageRoleUc),
		authUserHandler:     user_handlers.NewAuthenticatedUserHandler(getAuthUserUc),
		AuthMiddleware: middlewares.JWTMiddleware(
			jwtService,
			deviceRepo,
		),
	}, nil
}
