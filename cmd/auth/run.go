package main

import (
	"context"
	"log/slog"
	"time"

	"go_auth/internal/core/application"
)

func (c *container) run() {
	// Seed Super Admin
	seedCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := c.uc.seedSA.Execute(seedCtx, application.RegisterUserCommand{
		Email:    c.config.Seed.AdminEmail,
		Password: c.config.Seed.AdminPassword,
	})
	if err != nil {
		c.logger.Warn("seed_admin_skipped", slog.Any("error", err))
	}

	// Start HTTP
	go func() {
		c.logger.Info("server_starting",
			slog.String("port", c.config.HTTP.Port),
			slog.String("env", c.config.App.Env),
		)

		if err := c.app.Listen(":" + c.config.HTTP.Port); err != nil {
			c.logger.Error("server_failed", slog.Any("error", err))
		}
	}()

	// Wait shutdown
	waitForShutdown(c.app)
}
