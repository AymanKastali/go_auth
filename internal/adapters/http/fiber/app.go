package fiber

import (
	"go_auth/internal/adapters/http/fiber/api/v1/routes"
	"go_auth/internal/adapters/http/fiber/middlewares"
	"log/slog"

	_ "go_auth/docs"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/recover"
	"github.com/gofiber/fiber/v3/middleware/requestid"
	"github.com/gofiber/swagger/v2"
)

func NewFiberApp(d *Deps, name string, l *slog.Logger) *fiber.App {
	app := fiber.New(fiber.Config{
		AppName:      name,
		ErrorHandler: middlewares.NewGlobalErrorHandler(l),
	})

	app.Get("/swagger/*", swagger.HandlerDefault)

	// Middlewares
	app.Use(requestid.New())
	app.Use(middlewares.NewContextMiddleware(l))
	app.Use(recover.New())

	// Routes
	registerRoutes(app, d)

	app.Get("/health", func(c fiber.Ctx) error {
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
