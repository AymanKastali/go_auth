package routes

import (
	"go_auth/src/presentation/web/fiber/api/v1/controllers"

	"github.com/gofiber/fiber/v2"
)

func RegisterUserRoutes(
	app *fiber.App,
	controller *controllers.UserController,
	tokenMiddleware fiber.Handler,
) {
	userRoutes := app.Group("/api/v1/users")
	userRoutes.Get("/me", tokenMiddleware, controller.Me)

	// Register endpoints
	// api.Post("/register", endpoints.RegisterEndpoint(registerController))
	// api.Post("/login", endpoints.LoginEndpoint(loginController))
}
