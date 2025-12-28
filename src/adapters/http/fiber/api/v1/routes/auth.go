package routes

import (
	auth_handlers "go_auth/src/adapters/http/fiber/api/v1/handlers/auth"
	"go_auth/src/adapters/http/fiber/middlewares"
	"go_auth/src/domain/value_objects"

	"github.com/gofiber/fiber/v2"
)

func RegisterAuthRoutes(
	app *fiber.App,
	registerHandler *auth_handlers.RegisterHandler,
	loginHandler *auth_handlers.LoginHandler,
	refreshTokenHandler *auth_handlers.RefreshTokenHandler,
	logoutHandler *auth_handlers.LogoutHandler,
	rolesHandler *auth_handlers.RoleHandler,
	tokenMiddleware fiber.Handler,
) {
	authRoutes := app.Group("/api/v1/auth")
	authRoutes.Post("/register", registerHandler.Execute)
	authRoutes.Post("/login", loginHandler.Execute)
	authRoutes.Post("/logout", tokenMiddleware, loginHandler.Execute)
	authRoutes.Post("/refresh", refreshTokenHandler.Execute)
	authRoutes.Patch(
		"/roles",
		tokenMiddleware,
		middlewares.RequireRole(value_objects.RoleAdmin),
		rolesHandler.HandleRoleUpdate,
	)
}
