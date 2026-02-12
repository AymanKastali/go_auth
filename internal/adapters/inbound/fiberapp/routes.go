package fiberapp

import (
	_ "go_auth/docs"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/swagger/v2"
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
	app.Get("/swagger/*", swagger.HandlerDefault)

	api := app.Group("/api/v1")
	policy.RegisterRoutes(api)
	auth.RegisterRoutes(api.Group("/auth"))

	users := api.Group("/users")
	users.Use(authGuard)
	user.RegisterRoutes(users)

	adminGroup := api.Group("/admin")
	adminGroup.Use(authGuard)
	adminGroup.Use(RequireRole("super_admin", "admin"))
	admin.RegisterRoutes(adminGroup)
}
