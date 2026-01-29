package bootstrap

import (
	"go_auth/internal/adapters"
	"go_auth/internal/adapters/http/fiberapp"
	"go_auth/internal/core/application"
	"log/slog"

	"github.com/gofiber/fiber/v3"
)

func NewApp(
	cfg adapters.AppConfig,
	handlers Handlers,
	idGen application.IIDGenerator,
	baseLogger *slog.Logger,
) (*fiber.App, Handlers) {
	app := fiber.New(fiber.Config{
		ErrorHandler: fiberapp.NewErrorHandler(),
		AppName:      cfg.Name,
	})

	fiberapp.ConfigureMiddlewares(app, baseLogger, idGen)
	fiberapp.RegisterRoutes(
		app,
		handlers.Auth,
		handlers.User,
		handlers.AuthGuard,
	)
	return app, handlers
}
