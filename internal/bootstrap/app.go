package bootstrap

import (
	"go_auth/internal/adapters"
	"go_auth/internal/adapters/http/fiberapp"
	"go_auth/internal/core/domain"
	"log/slog"

	"github.com/gofiber/fiber/v3"
)

func SetupApp(cfg adapters.AppConfig, uc UseCases, idGen domain.IIDGenerator, baseLogger *slog.Logger) (*fiber.App, Handlers) {
	// 1. Setup Handlers
	handlers := SetupHandlers(uc)

	// 2. Initialize Fiber with a global ErrorHandler
	app := fiber.New(fiber.Config{
		ErrorHandler: fiberapp.NewErrorHandler(),
		AppName:      cfg.Name,
	})

	// 3. Configure Middleware (RequestID, Logging, Context, Error handling)
	fiberapp.ConfigureMiddlewares(app, baseLogger, idGen)

	// 4. Register routes for all handlers (authGuard is required)
	fiberapp.RegisterRoutes(app, handlers.Auth, handlers.AuthGuard)

	return app, handlers
}
