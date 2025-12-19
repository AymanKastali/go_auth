package routes

import (
	"go_auth/src/presentation/web/fiber/api/v1/controllers"

	"github.com/gofiber/fiber/v2"
)

func RegisterOrganizationRoutes(
	app *fiber.App,
	controller *controllers.OrganizationController,
	authMiddleware fiber.Handler,
) {
	group := app.Group("/api/v1/organizations", authMiddleware)

	group.Post("/", controller.RegisterOrganization)
	group.Get("/", controller.ListUserOrganizations)
}
