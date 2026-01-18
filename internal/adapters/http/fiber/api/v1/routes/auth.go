package routes

import (
	"go_auth/internal/adapters/http/fiber/api/v1/handlers/auth"
	"go_auth/internal/adapters/http/fiber/api/v1/handlers/roles"
	"go_auth/internal/adapters/http/fiber/middlewares"

	"github.com/gofiber/fiber/v2"
)

func RegisterAuthRoutes(
	app *fiber.App,
	registerHandler *auth.RegisterHandler,
	loginHandler *auth.LoginHandler,
	refreshTokenHandler *auth.RefreshTokenHandler,
	logoutHandler *auth.LogoutHandler,
	rolesHandler *roles.UpdateRoleHandler,
	tokenMiddleware fiber.Handler,
) {
	authRoutes := app.Group("/api/v1/auth")
	authRoutes.Post(
		"/register",
		registerHandler.Execute,
	)
	authRoutes.Post(
		"/login",
		loginHandler.Execute,
	)
	authRoutes.Post(
		"/logout",
		tokenMiddleware,
		logoutHandler.Execute,
	)
	authRoutes.Post(
		"/refresh",
		refreshTokenHandler.Execute,
	)
	authRoutes.Patch(
		"/roles",
		tokenMiddleware,
		middlewares.RequireRole("admin"),
		rolesHandler.Execute,
	)
}
