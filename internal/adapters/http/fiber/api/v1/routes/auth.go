package routes

import (
	"go_auth/internal/adapters/http/fiber/api/v1/handlers/interfaces"
	"go_auth/internal/adapters/http/fiber/middlewares"

	"github.com/gofiber/fiber/v2"
)

func RegisterAuthRoutes(
	app *fiber.App,
	registerHandler interfaces.IRegisterHandler,
	loginHandler interfaces.ILoginHandler,
	refreshTokenHandler interfaces.IRefreshTokenHandler,
	logoutHandler interfaces.ILogoutHandler,
	rolesHandler interfaces.IUpdateRoleHandler,
	tokenMiddleware fiber.Handler,
) {
	authRoutes := app.Group("/api/v1/auth")
	authRoutes.Post("/register", registerHandler.Execute)
	authRoutes.Post("/login", loginHandler.Execute)
	authRoutes.Post("/logout", tokenMiddleware, logoutHandler.Execute)
	authRoutes.Post("/refresh", refreshTokenHandler.Execute)
	authRoutes.Patch(
		"/roles",
		tokenMiddleware,
		middlewares.RequireRole("admin"),
		rolesHandler.Execute,
	)
}
