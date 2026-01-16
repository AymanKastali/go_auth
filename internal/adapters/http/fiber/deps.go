package fiber

import (
	"go_auth/internal/adapters/http/fiber/api/v1/handlers/auth"
	"go_auth/internal/adapters/http/fiber/api/v1/handlers/roles"
	"go_auth/internal/adapters/http/fiber/api/v1/handlers/users"
	"go_auth/internal/adapters/http/fiber/middlewares"
	"go_auth/internal/adapters/persistence/postgres/mappers"
	"go_auth/internal/adapters/persistence/postgres/repositories"
	"go_auth/internal/adapters/seeder"
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
	RegisterHandler     *auth.RegisterHandler
	LoginHandler        *auth.LoginHandler
	RefreshTokenHandler *auth.RefreshTokenHandler
	LogoutHandler       *auth.LogoutHandler
	UpdateRoleHandler   *roles.UpdateRoleHandler
	AuthUserHandler     *users.AuthUserHandler
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
	jwtCfg, err := jwt.NewJWTConfig()
	if err != nil {
		return nil, err
	}
	jwtService := jwt.NewJWTService(jwtCfg)

	// -------------------
	// Seed admin
	// -------------------
	seederCfg, err := seeder.NewSeederConfig()
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
		RegisterHandler:     auth.NewRegisterHandler(registerUC, logger),
		LoginHandler:        auth.NewLoginHandler(loginUC),
		RefreshTokenHandler: auth.NewRefreshTokenHandler(refreshUC),
		LogoutHandler:       auth.NewLogoutHandler(logoutUC),
		UpdateRoleHandler:   roles.NewUpdateRoleHandler(roleUC),
		AuthUserHandler:     users.NewAuthUserHandler(authUserUC),
		AuthMiddleware: middlewares.JWTMiddleware(
			jwtService,
			deviceRepo,
			idSvc,
		),
		Logger: logger,
	}, nil
}
