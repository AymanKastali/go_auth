package bootstrap

import (
	"go_auth/src/application/handlers"
	"go_auth/src/domain/factories"
	"go_auth/src/infra/config"
	"go_auth/src/infra/mappers"
	"go_auth/src/infra/persistence/postgres/repositories"
	"go_auth/src/infra/security/jwt"
	"go_auth/src/infra/security/password"
	"go_auth/src/presentation/web/fiber/api/v1/controllers"
	"go_auth/src/presentation/web/fiber/middlewares"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

type deps struct {
	AuthController *controllers.AuthController
	UserController *controllers.UserController
	AuthMiddleware fiber.Handler
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

	// redisBlacklist := cache.NewRedisBlacklist(redis)

	// handlers
	registerHandler := handlers.NewRegisterHandler(
		userRepo,
		passwordHasher,
		idFactory,
		emailFactory,
		pwHashFactory,
		userFactory,
	)

	loginHandler := handlers.NewLoginHandler(
		userRepo,
		refreshTokenRepo,
		deviceRepo,
		passwordHasher,
		jwtService,
		emailFactory,
		deviceFactory,
	)

	logoutHandler := handlers.NewLogoutHandler(
		refreshTokenRepo,
		jwtService,
		idFactory,
	)

	refreshTokenHandler := handlers.NewRefreshTokenHandler(
		userRepo,
		refreshTokenRepo,
		jwtService,
		idFactory,
	)

	userHandler := handlers.NewUserHandler(
		userRepo,
		uuidMapper,
	)

	return &deps{
		AuthController: controllers.NewAuthController(
			registerHandler,
			loginHandler,
			logoutHandler,
			refreshTokenHandler,
		),
		UserController: controllers.NewUserController(userHandler),
		AuthMiddleware: middlewares.JWTMiddleware(
			jwtService,
			deviceRepo,
			idFactory,
		),
	}, nil
}
