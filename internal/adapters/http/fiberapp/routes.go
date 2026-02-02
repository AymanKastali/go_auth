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
	policyHandler *PolicyHandler,
	authGuard fiber.Handler,
) {
	app.Get("/swagger/*", swagger.HandlerDefault)

	api := app.Group("/api/v1")

	// Policies (public)
	api.Get("/policies", policyHandler.GetPublicPolicies)

	// Auth
	auth := api.Group("/auth")
	// Public
	auth.Post("/register", authHandler.Register)
	auth.Post("/login", authHandler.Login)
	auth.Post("/refresh", authHandler.Refresh)

	// Protected
	auth.Post("/logout", authGuard, authHandler.Logout)
	auth.Post("/reset-password", authHandler.ResetPassword)
	auth.Post("/forgot-password", authHandler.ForgotPassword)

	// Users
	users := api.Group("/users")
	users.Use(authGuard)
	users.Get("/me", userHandler.GetMe)      // Get own profile
	users.Patch("/me", userHandler.UpdateMe) // Update own profile
	users.Put("/me/password", userHandler.ChangePassword)
	users.Get("", userHandler.FindByEmail)
	users.Get("/:id", userHandler.GetByID)

	// Recovery Flow
	// auth.Post("/verify-email", authHandler.VerifyEmail) // Usually a GET or POST with token
}
