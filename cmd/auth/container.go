package main

import (
	"log/slog"

	"go_auth/internal/adapters"

	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
)

type container struct {
	config *adapters.Config
	logger *slog.Logger
	db     *gorm.DB

	domain      domainServices
	uc          useCases
	appServices applicationServices
	handlers    handlers
	app         *fiber.App
}

func newContainer() *container {
	c := &container{}

	c.config = loadConfig()
	c.logger = setupLogger(c.config.App.LogLevel)
	c.db = setupDatabase(c.config.Database.URL)
	c.domain = newDomainServices(c.config, c.db)
	c.uc = newUseCases(c.domain)
	c.appServices = newApplicationServices()
	c.handlers = newHandlers(c.uc)

	c.app, c.handlers = newApp(c.config.App, c.handlers, c.appServices.idGen, c.logger)

	return c
}
