package main

import (
	"go_auth/internal/adapters"
	"go_auth/internal/adapters/http/fiberapp"
	"log/slog"

	"github.com/gofiber/fiber/v3"
)

func newApp(
	cfg adapters.AppConfig,
	h handlers,
	idGen fiberapp.IIDGenerator,
	baseLogger *slog.Logger,
) (*fiber.App, handlers) {
	app := fiber.New(fiber.Config{
		ErrorHandler: fiberapp.NewErrorHandler(),
		AppName:      cfg.Name,
	})

	fiberapp.ConfigureMiddlewares(app, baseLogger, idGen)
	fiberapp.RegisterRoutes(
		app,
		h.auth,
		h.user,
		h.authGuard,
	)
	return app, h
}
