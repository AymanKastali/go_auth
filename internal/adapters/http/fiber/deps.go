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

	tokenHasher := adaptersvc.NewHMACHasher([]byte("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY=="))
	tokenGenerator := adaptersvc.NewCryptoRandomTokenGenerator() // implements IRandomTokenGenerator

	// -------------------
	// Mappers
	// -------------------
	userMapper := mappers.NewUserMapper()
	roleMapper := mappers.NewRoleMapper()
	deviceMapper := mappers.NewDeviceMapper()
	refreshTokenMapper := mappers.NewRenewalTokenMapper()

	// -------------------
	// Repositories
	// -------------------
	userRepo := repositories.NewGormUserRepository(db, userMapper, idSvc, pwdHashSvc)
	roleRepo := repositories.NewGormRoleRepository(db, roleMapper, idSvc)
	deviceRepo := repositories.NewGormDeviceRepository(db, deviceMapper, idSvc)
	refreshTokenRepo := repositories.NewGormRenewalTokenRepository(db, refreshTokenMapper)

	// -------------------
	// Security services (JWT)
	// -------------------
	jwtCfg, err := jwt.NewJWTCfg()
	if err != nil {
		return nil, err
	}
	jwtSvc := jwt.NewJWTSessionTokenIssuerService(jwtCfg.PrivateKey(), jwtCfg.PublicKey(), jwtCfg.Issuer(), jwtCfg.Audience())

	// -------------------
	// Seed default roles and admin
	// -------------------
	seederCfg, err := seeder.NewSeederConfig()
	if err != nil {
		return nil, err
	}

	if err := services.NewSeedRolesSvc(roleRepo, idSvc, clockSvc, logger).SeedDefaultRoles(); err != nil {
		log.Fatal(err)
	}

	if err := services.NewSeedAdminSvc(userRepo, roleRepo, pwdHashSvc, idSvc, clockSvc, seederCfg, logger).SeedAdmin(); err != nil {
		log.Fatal(err)
	}

	// -------------------
	// Domain services & factories
	// -------------------
	registrationPolicy := domainsvc.NewDefaultUserRegistrationPolicy(userRepo, roleRepo)
	userFactory := factories.NewDefaultUserFactory(registrationPolicy, idSvc, clockSvc)

	// -------------------
	// Use cases
	// -------------------
	registerUC := usecases.NewRegisterUseCase(userRepo, pwdHashSvc, userFactory)

	loginUC := usecases.NewLoginUseCase(
		userRepo,
		refreshTokenRepo,
		deviceRepo,
		roleRepo,
		pwdHashSvc,
		jwtSvc,
		idSvc,
		clockSvc,
		tokenHasher,
		tokenGenerator,
	)

	refreshUC := usecases.NewRenewalTokenUseCase( // renamed to match your latest code
		userRepo,
		refreshTokenRepo,
		deviceRepo,
		roleRepo,
		jwtSvc,
		idSvc,
		clockSvc,
		tokenHasher,
		tokenGenerator,
	)

	logoutUC := usecases.NewLogoutUseCase(refreshTokenRepo, clockSvc, tokenHasher)
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
