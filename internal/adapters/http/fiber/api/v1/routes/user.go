package routes

import (
	"go_auth/internal/adapters/http/fiber/api/v1/handlers/users"

	"github.com/gofiber/fiber/v2"
)

func RegisterUserRoutes(
	app *fiber.App,
	getAuthUserHandler *users.AuthUserHandler,
	tokenMiddleware fiber.Handler,
) {
	userRoutes := app.Group("/api/v1/users")
	userRoutes.Get(
		"/me",
		tokenMiddleware,
		getAuthUserHandler.Execute,
	)
}
