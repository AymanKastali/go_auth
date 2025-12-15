package main

import (
	usecases "go_auth/src/application/use_cases"
	"go_auth/src/domain/factories"
	"go_auth/src/infra/config"
	"go_auth/src/infra/mappers"
	"go_auth/src/infra/persistence/postgres"
	"go_auth/src/infra/persistence/postgres/repositories"
	"go_auth/src/infra/services/jwt"
	"go_auth/src/infra/services/password"
	"go_auth/src/presentation/web/fiber/api/v1/controllers"
	"go_auth/src/presentation/web/fiber/api/v1/routes"
	"go_auth/src/presentation/web/fiber/middleware"
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"gorm.io/gorm"
)

func main() {
	// ----------------------
	// Fiber App
	// ----------------------
	app := fiber.New()

	// Middleware
	app.Use(recover.New())
	app.Use(logger.New())

	// Health endpoint
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	// ----------------------
	// Database
	// ----------------------
	var db *gorm.DB
	var err error
	db, err = postgres.NewPostgresConnection()
	if err != nil {
		log.Fatal("Could not connect to Postgres:", err)
	}

	// Auto-migrate entities
	postgres.AutoMigrate(db)

	// Domain Factories (Stateless, no dependencies, but good practice to initialize once)
	idFactory := factories.IDFactory{}
	emailFactory := factories.EmailFactory{}
	pwHashFactory := factories.PasswordHashFactory{}
	userFactory := factories.UserFactory{}

	// Infrastructure Mappers (Stateless)
	// permMapper := mappers.PermissionMapper{}
	// roleMapper := mappers.RoleMapper{}
	userMapper := mappers.UserMapper{}
	uuidMapper := mappers.UUIDMapper{}

	// ----------------------
	// Infrastructure
	// ----------------------
	userRepo := repositories.NewGormUserRepository(db, userMapper)
	// roleRepo := repositories.NewGormRoleRepository(db, roleMapper)
	// permRepo := repositories.NewGormPermissionRepository(db, permMapper)

	passwordHasher := password.NewBcryptPasswordHasher(12)
	jwt_cfg, err := config.LoadJWTConfigFromEnv()
	if err != nil {
		log.Fatal(err)
	}
	jwtService := jwt.NewJWTService(jwt_cfg)

	// ----------------------
	// Use Cases
	// ----------------------
	registerUseCase := usecases.NewRegisterUseCase(
		userRepo,
		passwordHasher,
		idFactory,
		emailFactory,
		pwHashFactory,
		userFactory,
	)

	loginUseCase := usecases.NewLoginUseCase(
		userRepo,
		passwordHasher,
		jwtService,
		emailFactory, // Required by LoginUC
	)

	userUseCase := usecases.NewUserUseCase(
		userRepo,
		uuidMapper,
	)

	// ----------------------
	// Controllers
	// ----------------------
	registerController := controllers.NewRegisterController(registerUseCase)
	loginController := controllers.NewLoginController(loginUseCase)
	getAuthenticatedUserController := controllers.NewUserController(userUseCase)

	// ----------------------
	// Routes
	// ----------------------
	routes.RegisterAuthRoutes(app, registerController, loginController)
	authMiddleware := middleware.JWTMiddleware(jwtService)
	routes.RegisterUserRoutes(app, getAuthenticatedUserController, authMiddleware)

	// ----------------------
	// Start server
	// ----------------------
	log.Println("Fiber server running on :8080")
	if err := app.Listen(":8080"); err != nil {
		log.Fatal(err)
	}
}
