package routes

import (
	"go_auth/src/presentation/web/fiber/api/v1/controllers"

	"github.com/gofiber/fiber/v2"
)

func RegisterOrganizationRoutes(
	app *fiber.App,
	controller *controllers.RegisterOrganizationController,
	authMiddleware fiber.Handler,
) {
	group := app.Group("/api/v1/organizations", authMiddleware)

	group.Post("/", controller.Handle)
}
