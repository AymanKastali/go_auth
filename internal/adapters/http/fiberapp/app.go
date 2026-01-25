package fiberapp

import (
	"github.com/gofiber/fiber/v3"
)

func SetupApp(handler *AuthHandler, middleware fiber.Handler) *fiber.App {
	// 1. Initialize App with the Global Error Handler
	app := fiber.New(fiber.Config{
		// ErrorHandler: GlobalErrorHandler, // The explicit mapper we discussed
		AppName: "AuthService v1.0",
	})

	// 2. Base API Group
	api := app.Group("/api/v1")

	// 3. Public Routes (No Auth Needed)
	auth := api.Group("/auth")
	auth.Post("/register", handler.Register)
	auth.Post("/login", handler.Login)
	auth.Post("/refresh", handler.Refresh) // Usually public as it carries the RT

	// 4. Protected Routes (Identity Guard Required)
	// This ensures Logout always has the Locals it needs
	protected := api.Group("/auth", middleware)
	protected.Post("/logout", handler.Logout)

	return app
}
