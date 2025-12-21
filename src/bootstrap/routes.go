package bootstrap

import (
	"go_auth/src/presentation/web/fiber/api/v1/routes"

	"github.com/gofiber/fiber/v2"
)

func registerRoutes(app *fiber.App, d *deps) {
	routes.RegisterAuthRoutes(app, d.AuthController)
	routes.RegisterUserRoutes(app, d.UserController, d.AuthMiddleware)
}
