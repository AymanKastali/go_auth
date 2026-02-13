package fiberapp

import (
	_ "go_auth/docs"

	"github.com/gofiber/contrib/v3/swaggo"
	"github.com/gofiber/fiber/v3"
)

func SetupRoutes(
	app *fiber.App,
	health *HealthController,
	auth *AuthController,
	user *UserController,
	policy *PolicyController,
	admin *AdminController,
	authGuard fiber.Handler,
) {
	health.RegisterRoutes(app)
	app.Get("/swagger/*", swaggo.HandlerDefault)

	api := app.Group("/api/v1")
	policy.RegisterRoutes(api)

	authGroup := api.Group("/auth")
	authGroup.Use(NewAuthRateLimiter())
	auth.RegisterRoutes(authGroup)

	users := api.Group("/users")
	users.Use(authGuard)
	user.RegisterRoutes(users)

	adminGroup := api.Group("/admin")
	adminGroup.Use(authGuard)
	adminGroup.Use(RequireRole("super_admin", "admin"))
	admin.RegisterRoutes(adminGroup)
}
