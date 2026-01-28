package bootstrap

import (
	"context"
	"log/slog"
	"time"

	"go_auth/internal/core/application"
)

func (c *fiberPostgresContainer) Run() {
	// Seed Super Admin
	seedCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := c.UC.SeedSA.Execute(seedCtx, application.RegisterUserCommand{
		Email:    c.Config.Seed.AdminEmail,
		Password: c.Config.Seed.AdminPassword,
	})
	if err != nil {
		c.Logger.Warn("seed_admin_skipped", slog.Any("error", err))
	}

	// Start HTTP
	go func() {
		c.Logger.Info("server_starting",
			slog.String("port", c.Config.HTTP.Port),
			slog.String("env", c.Config.App.Env),
		)

		if err := c.App.Listen(":" + c.Config.HTTP.Port); err != nil {
			c.Logger.Error("server_failed", slog.Any("error", err))
		}
	}()

	// Wait shutdown
	WaitForShutdown(c.App)
}
