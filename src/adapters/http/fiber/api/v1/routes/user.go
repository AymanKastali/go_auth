package routes

import (
	user_handlers "go_auth/src/adapters/http/fiber/api/v1/handlers/user"

	"github.com/gofiber/fiber/v2"
)

func RegisterUserRoutes(
	app *fiber.App,
	getAuthUserHandler *user_handlers.AuthenticatedUserHandler,
	tokenMiddleware fiber.Handler,
) {
	userRoutes := app.Group("/api/v1/users")
	userRoutes.Get("/me", tokenMiddleware, getAuthUserHandler.Execute)
}
