package fiber

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
	"os"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

type Deps struct {
	RegisterHandler     *auth_handlers.RegisterHandler
	LoginHandler        *auth_handlers.LoginHandler
	RefreshTokenHandler *auth_handlers.RefreshTokenHandler
	LogoutHandler       *auth_handlers.LogoutHandler
	RoleHandler         *auth_handlers.RoleHandler
	AuthUserHandler     *user_handlers.AuthenticatedUserHandler
	AuthMiddleware      fiber.Handler
	Logger              *slog.Logger
}

func InitDeps(db *gorm.DB) (*Deps, error) {
	// -------------------
	// Logger
	// -------------------
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	// -------------------
	// Mappers
	// -------------------
	userMapper := mappers.NewUserMapper()
	deviceMapper := mappers.NewDeviceMapper()
	refreshTokenMapper := mappers.NewRefreshTokenMapper()

	// -------------------
	// Repositories
	// -------------------
	userRepo := repositories.NewGormUserRepository(db, userMapper)
	deviceRepo := repositories.NewGormDeviceRepository(db, deviceMapper)
	refreshTokenRepo := repositories.NewGormRefreshTokenRepository(db, refreshTokenMapper)

	// -------------------
	// Security services
	// -------------------
	passwordHasher := password.NewBcryptHashedPassworder(12)

	jwtCfg, err := config.LoadJWTConfigFromEnv()
	if err != nil {
		return nil, err
	}
	jwtService := jwt.NewJWTService(jwtCfg)

	// -------------------
	// Seed admin
	// -------------------
	seederCfg, err := config.LoadSeederConfig()
	if err != nil {
		return nil, err
	}
	seeder := services.NewSeedAdminService(
		userRepo,
		passwordHasher,
		seederCfg,
		logger,
	)
	if err := seeder.SeedAdmin(); err != nil {
		log.Fatal(err)
	}

	// -------------------
	// Use cases
	// -------------------
	registerUC := use_cases.NewRegisterUseCase(
		userRepo,
		passwordHasher,
		logger,
	)

	loginUC := use_cases.NewLoginUseCase(
		userRepo,
		refreshTokenRepo,
		deviceRepo,
		passwordHasher,
		jwtService,
		logger,
	)

	logoutUC := use_cases.NewLogoutUseCase(
		refreshTokenRepo,
		jwtService,
		logger,
	)

	refreshUC := use_cases.NewRefreshTokenUseCase(
		userRepo,
		refreshTokenRepo,
		deviceRepo,
		jwtService,
		logger,
	)

	authUserUC := use_cases.NewAuthenticatedUserUseCase(
		userRepo,
		logger,
	)

	roleUC := use_cases.NewManageRoleUseCase(
		userRepo,
		logger,
	)

	// -------------------
	// Handlers
	// -------------------
	return &Deps{
		RegisterHandler:     auth_handlers.NewRegisterHandler(registerUC),
		LoginHandler:        auth_handlers.NewLoginHandler(loginUC),
		RefreshTokenHandler: auth_handlers.NewRefreshTokenHandler(refreshUC),
		LogoutHandler:       auth_handlers.NewLogoutHandler(logoutUC),
		RoleHandler:         auth_handlers.NewRoleHandler(roleUC),
		AuthUserHandler:     user_handlers.NewAuthenticatedUserHandler(authUserUC),
		AuthMiddleware:      middlewares.JWTMiddleware(jwtService, deviceRepo),
		Logger:              logger,
	}, nil
}
