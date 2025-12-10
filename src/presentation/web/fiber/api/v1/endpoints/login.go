package endpoints

import (
	"go_auth/src/presentation/web/fiber/api/v1/controllers"

	"github.com/gofiber/fiber/v2"
)

func LoginEndpoint(controller *controllers.LoginController) fiber.Handler {
	return func(c *fiber.Ctx) error {
		return controller.Execute(c)
	}
}
