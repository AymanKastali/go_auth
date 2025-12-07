package fiber

import (
	"github.com/gofiber/fiber/v2"
)

func NewServer(authHandlers *AuthHandlers, jwtMiddleware fiber.Handler) *fiber.App {
	app := fiber.New()
	api := app.Group("/api")
	api.Post("/register", authHandlers.Register)
	api.Post("/login", authHandlers.Login)

	protected := api.Group("/me", jwtMiddleware)
	protected.Get("/", func(c *fiber.Ctx) error {
		uid := c.Locals("user_id")
		return c.JSON(fiber.Map{"user_id": uid})
	})
	return app
}
