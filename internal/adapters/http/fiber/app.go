package fiber

import (
	"go_auth/internal/adapters/http/fiber/api/v1/routes"
	"go_auth/internal/adapters/http/fiber/middlewares"
	"go_auth/internal/adapters/http/fiber/utils"
	"log/slog"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/requestid"
)

func NewFiberApp(d *Deps, cfg *FiberConfig, l *slog.Logger) *fiber.App {
	app := fiber.New(fiber.Config{
		AppName:      cfg.AppName(),
		ErrorHandler: middlewares.NewGlobalErrorHandler(l),
	})

	// Middlewares
	app.Use(requestid.New())
	// This packs the RequestID, IP, DeviceID, etc., into dto.ContextKey
	app.Use(func(c *fiber.Ctx) error {
		utils.SetContext(c)
		return c.Next()
	})

	app.Use(recover.New())

	// Routes
	registerRoutes(app, d)

	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	return app
}

func registerRoutes(app *fiber.App, d *Deps) {
	routes.RegisterAuthRoutes(
		app,
		d.RegisterHandler,
		d.LoginHandler,
		d.RefreshTokenHandler,
		d.LogoutHandler,
		d.UpdateRoleHandler,
		d.AuthMiddleware,
	)
	routes.RegisterUserRoutes(app,
		d.AuthUserHandler,
		d.AuthMiddleware,
	)
}
