package fiber

import (
	"go_auth/internal/adapters/http/fiber/api/v1/routes"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

func NewFiberApp(d *Deps, cfg *FiberConfig) *fiber.App {
	app := fiber.New(fiber.Config{
		AppName:      cfg.AppName(),
		ErrorHandler: defaultErrorHandler,
	})

	// Middlewares
	app.Use(recover.New())
	app.Use(logger.New())

	// Routes
	registerRoutes(app, d)

	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	return app
}

func defaultErrorHandler(c *fiber.Ctx, err error) error {
	// You can inspect err and return proper JSON
	code := fiber.StatusInternalServerError
	msg := err.Error()
	return c.Status(code).JSON(fiber.Map{
		"error": msg,
	})
}

func registerRoutes(app *fiber.App, d *Deps) {
	routes.RegisterAuthRoutes(
		app,
		d.RegisterHandler,
		d.LoginHandler,
		d.RefreshTokenHandler,
		d.LogoutHandler,
		d.RoleHandler,
		d.AuthMiddleware,
	)
	routes.RegisterUserRoutes(app,
		d.AuthUserHandler,
		d.AuthMiddleware,
	)
}
