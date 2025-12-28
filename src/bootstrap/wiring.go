package bootstrap

import (
	"go_auth/src/adapters/config"
	auth_handlers "go_auth/src/adapters/http/fiber/api/v1/handlers/auth"
	user_handlers "go_auth/src/adapters/http/fiber/api/v1/handlers/user"
	"go_auth/src/adapters/http/fiber/middlewares"
	"go_auth/src/adapters/mappers"
	"go_auth/src/adapters/persistence/postgres/repositories"
	"go_auth/src/adapters/security/jwt"
	"go_auth/src/adapters/security/password"
	"go_auth/src/application/services"
	"go_auth/src/application/use_cases"
	"go_auth/src/domain/factories"
	"log"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

type deps struct {
	registerHandler     *auth_handlers.RegisterHandler
	loginHandler        *auth_handlers.LoginHandler
	refreshTokenHandler *auth_handlers.RefreshTokenHandler
	logoutHandler       *auth_handlers.LogoutHandler
	authUserHandler     *user_handlers.AuthenticatedUserHandler
	AuthMiddleware      fiber.Handler
}

func wireDependencies(
	db *gorm.DB,
	// redis *redis.Client,
) (*deps, error) {
	// factories
	idFactory := factories.IDFactory{}
	emailFactory := factories.EmailFactory{}
	pwHashFactory := factories.PasswordHashFactory{}
	userFactory := factories.UserFactory{}
	deviceFactory := factories.NewDeviceFactory(idFactory)

	// infra
	uuidMapper := mappers.NewUUIDMapper()
	userMapper := mappers.NewUserMapper(uuidMapper)
	deviceMapper := mappers.NewDeviceMapper(uuidMapper)
	refreshTokenMapper := mappers.NewRefreshTokenMapper(uuidMapper)

	userRepo := repositories.NewGormUserRepository(db, userMapper)
	refreshTokenRepo := repositories.NewGormRefreshTokenRepository(db, refreshTokenMapper)
	deviceRepo := repositories.NewGormDeviceRepository(db, deviceMapper)

	passwordHasher := password.NewBcryptPasswordHasher(12)

	jwtCfg, err := config.LoadJWTConfigFromEnv()
	if err != nil {
		return nil, err
	}
	jwtService := jwt.NewJWTService(jwtCfg, idFactory)

	seederCfg, err := config.LoadSeederConfig()
	if err != nil {
		return nil, err
	}

	seeder := services.NewSeedAdminService(
		userRepo,
		passwordHasher,
		pwHashFactory,
		userFactory,
		idFactory,
		seederCfg,
	)

	if err := seeder.SeedAdmin(); err != nil {
		log.Fatal(err)
	}

	// redisBlacklist := cache.NewRedisBlacklist(redis)

	// handlers
	RegisterUseCase := use_cases.NewRegisterUseCase(
		userRepo,
		passwordHasher,
		idFactory,
		emailFactory,
		pwHashFactory,
		userFactory,
	)

	LoginUseCase := use_cases.NewLoginUseCase(
		userRepo,
		refreshTokenRepo,
		deviceRepo,
		passwordHasher,
		jwtService,
		emailFactory,
		deviceFactory,
	)

	LogoutUseCase := use_cases.NewLogoutUseCase(
		refreshTokenRepo,
		jwtService,
		idFactory,
	)

	RefreshTokenUseCase := use_cases.NewRefreshTokenUseCase(
		userRepo,
		refreshTokenRepo,
		jwtService,
		idFactory,
	)

	userHandler := use_cases.NewAuthenticatedUserUseCase(
		userRepo,
		uuidMapper,
	)

	return &deps{
		registerHandler:     auth_handlers.NewRegisterHandler(RegisterUseCase),
		loginHandler:        auth_handlers.NewLoginHandler(LoginUseCase),
		logoutHandler:       auth_handlers.NewLogoutHandler(LogoutUseCase),
		refreshTokenHandler: auth_handlers.NewRefreshTokenHandler(RefreshTokenUseCase),
		authUserHandler:     user_handlers.NewAuthenticatedUserHandler(userHandler),
		AuthMiddleware: middlewares.JWTMiddleware(
			jwtService,
			deviceRepo,
			idFactory,
		),
	}, nil
}
