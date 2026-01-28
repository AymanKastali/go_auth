package fiberapp

import (
	_ "go_auth/docs"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/swagger/v2"
)

func RegisterRoutes(
	app *fiber.App,
	authHandler *AuthHandler,
	userHandler *UserHandler,
	authGuard fiber.Handler,
) {
	app.Get("/swagger/*", swagger.HandlerDefault)

	api := app.Group("/api/v1")

	// Auth
	auth := api.Group("/auth")
	// Public
	auth.Post("/register", authHandler.Register)
	auth.Post("/login", authHandler.Login)
	auth.Post("/refresh", authHandler.Refresh)

	// Protected
	auth.Post("/logout", authGuard, authHandler.Logout)

	// Users
	users := api.Group("/users")
	users.Use(authGuard)
	users.Get("", userHandler.FindByEmail)
}
