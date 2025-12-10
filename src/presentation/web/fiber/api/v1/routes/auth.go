package routes

import (
	"go_auth/src/presentation/web/fiber/api/v1/controllers"
	"go_auth/src/presentation/web/fiber/api/v1/endpoints"

	"github.com/gofiber/fiber/v2"
)

// RegisterAuthRoutes wires the Auth endpoints to the Fiber app
func RegisterAuthRoutes(
	app *fiber.App,
	registerController *controllers.RegisterController,
	loginController *controllers.LoginController,
) {
	api := app.Group("/api/v1/auth")

	// Register endpoints
	api.Post("/register", endpoints.RegisterEndpoint(registerController))
	api.Post("/login", endpoints.LoginEndpoint(loginController))
}
