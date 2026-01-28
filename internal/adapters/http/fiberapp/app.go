package fiberapp

import (
	"go_auth/internal/adapters"
	"go_auth/internal/core/domain"
	"log/slog"

	"github.com/gofiber/fiber/v3"
)

func SetupApp(cfg adapters.AppConfig, handler *AuthHandler, authGuard fiber.Handler, baseLogger *slog.Logger, idGen domain.IIDGenerator) *fiber.App {
	app := fiber.New(fiber.Config{
		ErrorHandler: NewErrorHandler(),
		AppName:      cfg.Name,
	})

	ConfigureMiddlewares(app, baseLogger, idGen)
	RegisterRoutes(app, handler, authGuard)

	return app
}
