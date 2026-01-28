package fiberapp

import (
	"go_auth/internal/core/domain"
	"log/slog"

	"github.com/gofiber/fiber/v3"
)

func SetupApp(handler *AuthHandler, authGuard fiber.Handler, baseLogger *slog.Logger, idGen domain.IIDGenerator) *fiber.App {
	app := fiber.New(fiber.Config{
		ErrorHandler: NewErrorHandler(),
		AppName:      "AuthService v1.0",
	})

	ConfigureMiddlewares(app, baseLogger, idGen)
	RegisterRoutes(app, handler, authGuard)

	return app
}
