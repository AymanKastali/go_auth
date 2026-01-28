package bootstrap

import (
	"go_auth/internal/adapters"
	"go_auth/internal/adapters/http/fiberapp"
	"go_auth/internal/core/domain"
	"log/slog"

	"github.com/gofiber/fiber/v3"
)

func SetupHTTP(cfg adapters.AppConfig, u UseCases, ulidGen domain.IIDGenerator, logger *slog.Logger) *fiber.App {
	handler := fiberapp.NewAuthHandler(
		u.Register,
		u.Login,
		u.Refresh,
		u.Logout,
		u.Validate,
	)

	middleware := fiberapp.Protected(u.Validate)
	return fiberapp.SetupApp(cfg, handler, middleware, logger, ulidGen)
}
