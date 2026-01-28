package fiberapp

import (
	_ "go_auth/docs"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/swagger/v2"
)

func RegisterRoutes(app *fiber.App, handler *AuthHandler, authMiddleware fiber.Handler) {
	app.Get("/swagger/*", swagger.HandlerDefault)

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
