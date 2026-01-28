package fiberapp

import "github.com/gofiber/fiber/v3"

func RegisterRoutes(app *fiber.App, handler *AuthHandler, authMiddleware fiber.Handler) {
	api := app.Group("/api/v1")

	auth := api.Group("/auth")
	// Public
	auth.Post("/register", handler.Register)
	auth.Post("/login", handler.Login)
	auth.Post("/refresh", handler.Refresh)

	// Protected
	protected := api.Group("/auth", authMiddleware)
	protected.Post("/logout", handler.Logout)
}
