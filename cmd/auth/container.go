package main

import (
	"log/slog"

	"go_auth/internal/adapters"
	"go_auth/internal/adapters/persistence/postgres"

	"github.com/gofiber/fiber/v3"
)

type container struct {
	config      *adapters.Config
	logger      *slog.Logger
	persistence *postgres.PersistenceFactory

	domain   domainServices
	appInfra applicationInfra
	uc       useCases
	handlers handlers
	app      *fiber.App
}

func newContainer() (*container, error) {
	c := &container{}

	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	c.config = cfg

	c.logger = setupLogger(c.config.App.LogLevel)
	c.persistence = setupDatabase(c.config.Database.URL)
	c.domain = newDomainServices(c.config, c.persistence)
	c.appInfra = newApplicationInfra(c.config, c.persistence, c.logger)
	c.uc = newUseCases(c.domain, c.appInfra, c.config)
	c.handlers = newHandlers(c.uc)

	c.app, c.handlers = newApp(c.config.App, c.handlers, c.logger)

	return c, nil
}
