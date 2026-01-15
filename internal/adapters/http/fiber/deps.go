package fiber

import (
	auth_handlers "go_auth/internal/adapters/http/fiber/api/v1/handlers/auth"
	"go_auth/internal/adapters/http/fiber/api/v1/handlers/interfaces"
	user_handlers "go_auth/internal/adapters/http/fiber/api/v1/handlers/user"
	"go_auth/internal/adapters/http/fiber/middlewares"
	"go_auth/internal/adapters/persistence/postgres/mappers"
	"go_auth/internal/adapters/persistence/postgres/repositories"
	"go_auth/internal/adapters/seed"
	adaptersvc "go_auth/internal/adapters/services"
	"go_auth/internal/adapters/services/jwt"
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

	// Clock Service
	clockService := adaptersvc.NewClockService()

	// UUID Service
	idSvc := adaptersvc.NewUUIDService()
	pwsHashSvc := adaptersvc.NewBcryptHashedPassword(12)

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
	userRepo := repositories.NewGormUserRepository(db, userMapper, idSvc, pwsHashSvc)
	roleRepo := repositories.NewGormRoleRepository(db, roleMapper, idSvc)
	deviceRepo := repositories.NewGormDeviceRepository(db, deviceMapper, idSvc)
	refreshTokenRepo := repositories.NewGormRefreshTokenRepository(db, refreshTokenMapper, idSvc)

	// -------------------
	// Security services
	// -------------------
	jwtCfg, err := jwt.LoadJWTConfig()
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
		idSvc,
		clockService,
		logger,
	)
	if err := rolesSeeder.SeedDefaultRoles(); err != nil {
		log.Fatal(err)
	}

	adminUserSeeder := services.NewSeedAdminService(
		userRepo,
		roleRepo,
		pwsHashSvc,
		idSvc,
		clockService,
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
		pwsHashSvc,
		idSvc,
		clockService,
		logger,
	)

	loginUC := usecases.NewLoginUseCase(
		userRepo,
		refreshTokenRepo,
		deviceRepo,
		roleRepo,
		pwsHashSvc,
		jwtService,
		idSvc,
		clockService,
		logger,
	)

	logoutUC := usecases.NewLogoutUseCase(
		refreshTokenRepo,
		jwtService,
		idSvc,
		clockService,
		logger,
	)

	refreshUC := usecases.NewRefreshTokenUseCase(
		userRepo,
		refreshTokenRepo,
		deviceRepo,
		roleRepo,
		jwtService,
		idSvc,
		clockService,
		logger,
	)

	authUserUC := usecases.NewAuthUserUseCase(
		userRepo,
		roleRepo,
		idSvc,
		logger,
	)

	roleUC := usecases.NewUpdateRoleUseCase(
		userRepo,
		roleRepo,
		idSvc,
		clockService,
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
		AuthMiddleware: middlewares.JWTMiddleware(
			jwtService,
			deviceRepo,
			idSvc,
		),
		Logger: logger,
	}, nil
}
