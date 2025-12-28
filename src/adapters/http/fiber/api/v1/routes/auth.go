package routes

import (
	auth_handlers "go_auth/src/adapters/http/fiber/api/v1/handlers/auth"

	"github.com/gofiber/fiber/v2"
)

func RegisterAuthRoutes(
	app *fiber.App,
	registerHandler *auth_handlers.RegisterHandler,
	loginHandler *auth_handlers.LoginHandler,
	refreshTokenHandler *auth_handlers.RefreshTokenHandler,
	logoutHandler *auth_handlers.LogoutHandler,
	tokenMiddleware fiber.Handler,
) {
	authRoutes := app.Group("/api/v1/auth")
	authRoutes.Post("/register", registerHandler.Execute)
	authRoutes.Post("/login", loginHandler.Execute)
	authRoutes.Post("/logout", tokenMiddleware, loginHandler.Execute)
	authRoutes.Post("/refresh", refreshTokenHandler.Execute)
}
