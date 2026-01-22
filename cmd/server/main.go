package main

import (
	"go_auth/config"
	"go_auth/internal/adapters/http/fiber"
	"go_auth/internal/adapters/persistence/postgres"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		slog.Error("Failed to load config", "error", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.Fiber.LogLevel}))

	db, err := postgres.NewPostgresConnection(cfg.Postgres.DSN)
	if err != nil {
		logger.Error("Database connection failed", "error", err)
		os.Exit(1)
	}

	postgres.AutoMigrate(db)

	deps, err := fiber.InitDeps(db, cfg, logger)
	if err != nil {
		logger.Error("Dependency initialization failed", "error", err)
		os.Exit(1)
	}

	app := fiber.NewFiberApp(deps, cfg.Fiber.AppName, logger)

	go func() {
		addr := cfg.Fiber.ListenAddr()
		logger.Info("Server starting", "addr", addr)
		if err := app.Listen(addr); err != nil {
			logger.Error("Server runtime failure", "error", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server")
	if err := app.Shutdown(); err != nil {
		logger.Error("Fiber shutdown failed", "error", err)
	}

	if err := postgres.Close(db); err != nil {
		logger.Error("Database close failed", "error", err)
	}

	logger.Info("Server stopped")
}
