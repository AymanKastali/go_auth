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
	healthHandler *HealthHandler,
	adminHandler *AdminHandler,
	authGuard fiber.Handler,
) {
	// Health endpoints (outside /api/v1)
	app.Get("/health", healthHandler.Health)
	app.Get("/ready", healthHandler.Ready)

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
	auth.Post("/activate", authHandler.ConfirmActivation)
	auth.Post("/resend-activation", authHandler.ResendActivation)

	// Token validation (public — used by other services)
	auth.Post("/validate", adminHandler.ValidateToken)

	// Protected
	auth.Post("/logout", authGuard, authHandler.Logout)
	auth.Post("/reset-password", authHandler.ResetPassword)
	auth.Post("/forgot-password", authHandler.ForgotPassword)

	// Users
	users := api.Group("/users")
	users.Use(authGuard)
	users.Get("/me", userHandler.GetMe)
	users.Patch("/me", userHandler.UpdateMe)
	users.Put("/me/password", userHandler.ChangePassword)
	users.Get("", userHandler.FindByEmail)
	users.Get("/:id", userHandler.GetByID)

	// Admin panel (protected + role guard)
	admin := api.Group("/admin")
	admin.Use(authGuard)
	admin.Use(RequireRole("super_admin", "admin"))

	// Role management
	admin.Get("/roles", adminHandler.ListRoles)
	admin.Get("/roles/:id", adminHandler.GetRole)
	admin.Post("/roles", adminHandler.CreateRole)
	admin.Post("/roles/:id/permissions", adminHandler.AssignPermission)
	admin.Delete("/roles/:id/permissions", adminHandler.RevokePermission)

	// User management
	admin.Get("/users", adminHandler.ListUsers)
	admin.Get("/users/:id", adminHandler.AdminGetUser)
	admin.Post("/users/:id/roles", adminHandler.AssignUserRole)
	admin.Delete("/users/:id/roles", adminHandler.RevokeUserRole)
	admin.Post("/users/:id/activate", adminHandler.ActivateUser)
	admin.Post("/users/:id/deactivate", adminHandler.DeactivateUser)
	admin.Delete("/users/:id", adminHandler.DeleteUser)

	// Seeding
	admin.Post("/seed/roles", adminHandler.SeedRoles)
}
