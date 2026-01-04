package routes

import (
	auth_handlers "go_auth/internal/adapters/http/fiber/api/v1/handlers/auth"
	"go_auth/internal/adapters/http/fiber/middlewares"

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
	authRoutes.Post("/register", registerHandler.Register)
	authRoutes.Post("/login", loginHandler.Login)
	authRoutes.Post("/logout", tokenMiddleware, logoutHandler.Execute)
	authRoutes.Post("/refresh", refreshTokenHandler.Execute)
	authRoutes.Patch(
		"/roles",
		tokenMiddleware,
		middlewares.RequireRole("ADMIN"),
		rolesHandler.HandleRoleUpdate,
	)
}
