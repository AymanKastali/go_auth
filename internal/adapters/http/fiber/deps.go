package fiber

import (
	"go_auth/internal/adapters/config"
	auth_handlers "go_auth/internal/adapters/http/fiber/api/v1/handlers/auth"
	"go_auth/internal/adapters/http/fiber/api/v1/handlers/interfaces"
	user_handlers "go_auth/internal/adapters/http/fiber/api/v1/handlers/user"
	"go_auth/internal/adapters/http/fiber/middlewares"
	"go_auth/internal/adapters/mappers"
	"go_auth/internal/adapters/persistence/postgres/repositories"
	"go_auth/internal/adapters/security/jwt"
	"go_auth/internal/adapters/security/password"
	"go_auth/internal/core/application/services"
	"go_auth/internal/core/application/usecases"
	"log"
	"log/slog"
	"os"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

type Deps struct {
	RegisterHandler     interfaces.IRegisterHandler
	LoginHandler        interfaces.ILoginHandler
	RefreshTokenHandler interfaces.IRefreshTokenHandler
	LogoutHandler       interfaces.ILogoutHandler
	UpdateRoleHandler   interfaces.IUpdateRoleHandler
	AuthUserHandler     *user_handlers.AuthUserHandler
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
	roleMapper := mappers.NewRoleMapper()
	deviceMapper := mappers.NewDeviceMapper()
	refreshTokenMapper := mappers.NewRefreshTokenMapper()

	// -------------------
	// Repositories
	// -------------------
	userRepo := repositories.NewGormUserRepository(db, userMapper)
	roleRepo := repositories.NewGormRoleRepository(db, roleMapper)
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
	rolesSeeder := services.NewSeedRolesService(
		roleRepo,
		logger,
	)
	if err := rolesSeeder.SeedDefaultRoles(); err != nil {
		log.Fatal(err)
	}

	adminUserSeeder := services.NewSeedAdminService(
		userRepo,
		roleRepo,
		passwordHasher,
		seederCfg,
		logger,
	)
	if err := adminUserSeeder.SeedAdmin(); err != nil {
		log.Fatal(err)
	}

	// -------------------
	// Use cases
	// -------------------
	registerUC := usecases.NewRegisterUseCase(
		userRepo,
		roleRepo,
		passwordHasher,
		logger,
	)

	loginUC := usecases.NewLoginUseCase(
		userRepo,
		refreshTokenRepo,
		deviceRepo,
		roleRepo,
		passwordHasher,
		jwtService,
		logger,
	)

	logoutUC := usecases.NewLogoutUseCase(
		refreshTokenRepo,
		jwtService,
		logger,
	)

	refreshUC := usecases.NewRefreshTokenUseCase(
		userRepo,
		refreshTokenRepo,
		deviceRepo,
		roleRepo,
		jwtService,
		logger,
	)

	authUserUC := usecases.NewAuthUserUseCase(
		userRepo,
		roleRepo,
		logger,
	)

	roleUC := usecases.NewUpdateRoleUseCase(
		userRepo,
		roleRepo,
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
		UpdateRoleHandler:   auth_handlers.NewUpdateRoleHandler(roleUC),
		AuthUserHandler:     user_handlers.NewAuthUserHandler(authUserUC),
		AuthMiddleware:      middlewares.JWTMiddleware(jwtService, deviceRepo),
		Logger:              logger,
	}, nil
}
