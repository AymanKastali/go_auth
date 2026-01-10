package fiber

import (
	auth_handlers "go_auth/internal/adapters/http/fiber/api/v1/handlers/auth"
	"go_auth/internal/adapters/http/fiber/api/v1/handlers/interfaces"
	user_handlers "go_auth/internal/adapters/http/fiber/api/v1/handlers/user"
	"go_auth/internal/adapters/http/fiber/middlewares"
	"go_auth/internal/adapters/persistence/postgres/mappers"
	"go_auth/internal/adapters/persistence/postgres/repositories"
	"go_auth/internal/adapters/seed"
	"go_auth/internal/adapters/services/jwt"
	"go_auth/internal/adapters/services/password"
	"go_auth/internal/adapters/services/uuid"
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

	// UUID Services
	uuidGenerator := uuid.NewUUIDUserIDGenerator()
	uuidParser := uuid.NewUUIDUserIDParser()

	// -------------------
	// Mappers
	// -------------------
	userMapper := mappers.NewUserMapper(uuidParser)
	roleMapper := mappers.NewRoleMapper()
	deviceMapper := mappers.NewDeviceMapper(uuidParser)
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

	jwtCfg, err := jwt.LoadJWTConfigFromEnv()
	if err != nil {
		return nil, err
	}
	jwtService := jwt.NewJWTService(jwtCfg)

	// -------------------
	// Seed admin
	// -------------------
	seederCfg, err := seed.LoadSeederConfig()
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
		uuidGenerator,
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
		uuidGenerator,
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
		uuidParser,
		logger,
	)

	authUserUC := usecases.NewAuthUserUseCase(
		userRepo,
		roleRepo,
		uuidParser,
		logger,
	)

	roleUC := usecases.NewUpdateRoleUseCase(
		userRepo,
		roleRepo,
		uuidParser,
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
