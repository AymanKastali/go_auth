package bootstrap

import (
	"log/slog"

	"go_auth/internal/adapters"

	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
)

type fiberPostgresContainer struct {
	Config *adapters.Config
	Logger *slog.Logger
	DB     *gorm.DB

	Domain   DomainServices
	UC       UseCases
	Handlers Handlers
	App      *fiber.App
}

func NewFiberPostgresContainer() *fiberPostgresContainer {
	c := &fiberPostgresContainer{}

	// Load config and logger
	c.Config = LoadConfig()
	c.Logger = SetupLogger(c.Config.App.LogLevel)

	// Setup database
	c.DB = SetupDatabase(c.Config.Database.URL)

	// Setup domain services
	c.Domain = SetupDomain(c.Config, c.DB)

	// Setup use cases
	c.UC = SetupUseCases(c.Domain)

	// Setup Fiber app with handlers
	c.App, c.Handlers = SetupApp(c.Config.App, c.UC, c.Domain.ULIDGen, c.Logger)

	return c
}
