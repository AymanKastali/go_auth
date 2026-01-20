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
	"go_auth/internal/core/domain/factories"
	domainsvc "go_auth/internal/core/domain/services"
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

	// -------------------
	// Domain / infra services
	// -------------------
	clockSvc := adaptersvc.NewClockSvc()
	idSvc := adaptersvc.NewUUIDSvc()
	pwdHashSvc := adaptersvc.NewBcryptHasher(12)

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
	userRepo := repositories.NewGormUserRepository(db, userMapper, idSvc, pwdHashSvc)
	roleRepo := repositories.NewGormRoleRepository(db, roleMapper, idSvc)
	deviceRepo := repositories.NewGormDeviceRepository(db, deviceMapper, idSvc)
	refreshTokenRepo := repositories.NewGormRefreshTokenRepository(db, refreshTokenMapper, idSvc)

	// -------------------
	// Security services
	// -------------------
	jwtCfg, err := jwt.NewJWTCfg()
	if err != nil {
		return nil, err
	}
	jwtSvc := jwt.NewJWTSvc(jwtCfg)

	// -------------------
	// Seed default roles and admin
	// -------------------
	seederCfg, err := seeder.NewSeederConfig()
	if err != nil {
		return nil, err
	}

	rolesSeeder := services.NewSeedRolesSvc(roleRepo, idSvc, clockSvc, logger)
	if err := rolesSeeder.SeedDefaultRoles(); err != nil {
		log.Fatal(err)
	}

	adminSeeder := services.NewSeedAdminSvc(userRepo, roleRepo, pwdHashSvc, idSvc, clockSvc, seederCfg, logger)
	if err := adminSeeder.SeedAdmin(); err != nil {
		log.Fatal(err)
	}

	// -------------------
	// Domain services & factories
	// -------------------
	registrationPolicy := domainsvc.NewDefaultUserRegistrationPolicy(userRepo, roleRepo)
	userFactory := factories.NewDefaultUserFactory(
		registrationPolicy,
		idSvc,
		clockSvc,
	)

	// -------------------
	// Use cases
	// -------------------
	registerUC := usecases.NewRegisterUseCase(
		userRepo,
		pwdHashSvc,
		userFactory,
	)

	loginUC := usecases.NewLoginUseCase(
		userRepo, refreshTokenRepo, deviceRepo, roleRepo,
		pwdHashSvc, jwtSvc, idSvc, clockSvc,
	)

	logoutUC := usecases.NewLogoutUseCase(refreshTokenRepo, jwtSvc, idSvc, clockSvc)
	refreshUC := usecases.NewRefreshTokenUseCase(userRepo, refreshTokenRepo, deviceRepo, roleRepo, jwtSvc, idSvc, clockSvc)
	authUserUC := usecases.NewAuthUserUseCase(userRepo, roleRepo, idSvc)
	roleUC := usecases.NewUpdateRoleUseCase(userRepo, roleRepo, idSvc, clockSvc)

	// -------------------
	// Handlers
	// -------------------
	return &Deps{
		RegisterHandler:     auth.NewRegisterHandler(registerUC),
		LoginHandler:        auth.NewLoginHandler(loginUC),
		RefreshTokenHandler: auth.NewRefreshTokenHandler(refreshUC),
		LogoutHandler:       auth.NewLogoutHandler(logoutUC),
		UpdateRoleHandler:   roles.NewUpdateRoleHandler(roleUC),
		AuthUserHandler:     users.NewAuthUserHandler(authUserUC),
		AuthMiddleware:      middlewares.JWTMiddleware(jwtSvc, deviceRepo, idSvc),
		Logger:              logger,
	}, nil
}
