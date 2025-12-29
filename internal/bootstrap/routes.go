package bootstrap

import (
	"go_auth/internal/adapters/http/fiber/api/v1/routes"

	"github.com/gofiber/fiber/v2"
)

func registerRoutes(app *fiber.App, d *deps) {
	routes.RegisterAuthRoutes(
		app,
		d.registerHandler,
		d.loginHandler,
		d.refreshTokenHandler,
		d.logoutHandler,
		d.roleHandler,
		d.AuthMiddleware,
	)
	routes.RegisterUserRoutes(app,
		d.authUserHandler,
		d.AuthMiddleware,
	)
}
