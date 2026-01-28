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

	c.Config = LoadConfig()
	c.Logger = SetupLogger(c.Config.App.LogLevel)
	c.DB = SetupDatabase(c.Config.Database.URL)
	c.Domain = NewDomainServices(c.Config, c.DB)
	c.UC = NewUseCases(c.Domain)
	c.Handlers = NewHandlers(c.UC)

	c.App, c.Handlers = NewApp(c.Config.App, c.Handlers, c.Domain.ULIDGen, c.Logger)

	return c
}
