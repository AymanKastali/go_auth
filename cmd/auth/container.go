package main

import (
	"log/slog"

	"go_auth/internal/adapters"

	"github.com/gofiber/fiber/v3"
)

type container struct {
	config *adapters.Config
	logger *slog.Logger

	outbound    outboundAdapters
	domain      domainLayer
	application applicationLayer
	inbound     inboundAdapters
	app         *fiber.App
}

func newContainer() (*container, error) {
	c := &container{}

	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	c.config = cfg

	c.logger = setupLogger(c.config.App.LogLevel)
	c.outbound = newOutboundAdapters(c.config, c.logger)
	c.domain = newDomainLayer(c.config, c.outbound.persistence)
	c.application = newApplicationLayer(c.domain, c.outbound, c.config)
	c.inbound = newInboundAdapters(c.application)

	c.app = newApp(c.config.App, c.inbound.fiber, c.logger)

	return c, nil
}
