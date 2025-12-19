package routes

import (
	"go_auth/src/presentation/web/fiber/api/v1/controllers"

	"github.com/gofiber/fiber/v2"
)

func RegisterAuthRoutes(
	app *fiber.App,
	controller *controllers.AuthController,
) {
	authRoutes := app.Group("/api/v1/auth")
	authRoutes.Post("/register", controller.Register)
	authRoutes.Post("/login", controller.Login)
}
