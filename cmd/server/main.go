package main

import (
	"go_auth/internal/adapters/http/fiber"
	"go_auth/internal/adapters/persistence/postgres"
	"go_auth/internal/adapters/persistence/postgres/pgerr"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// 1. Config & Logger Setup
	fiberCfg, err := fiber.NewFiberConfig()
	if err != nil {
		slog.Error("Failed to load fiber configuration", "error", err)
		os.Exit(1)
	}

	opts := &slog.HandlerOptions{Level: fiberCfg.LogLevel()}
	l := slog.New(slog.NewJSONHandler(os.Stdout, opts))
	slog.SetDefault(l)

	// 2. Database Initialization
	dbCfg, err := postgres.NewPostgresConfig()
	if err != nil {
		l.Error("Failed to load database configuration", "error", err)
		os.Exit(1)
	}

	db, err := postgres.NewPostgresConnection(dbCfg)
	if err != nil {
		if pgerr.IsUnavailable(err) {
			l.Error("CRITICAL: Database is unavailable", "error", err)
		}
		os.Exit(1)
	}

	// 3. Migration & Deps
	if err := postgres.AutoMigrate(db); err != nil {
		l.Error("Database migration failed", "error", err)
		os.Exit(1)
	}

	deps, err := fiber.InitDeps(db)
	if err != nil {
		l.Error("Failed to initialize dependencies", "error", err)
		os.Exit(1)
	}

	app := fiber.NewFiberApp(deps, fiberCfg, l)

	// 4. Server Execution
	go func() {
		addr := fiberCfg.ListenAddr()
		l.Info("Server is starting", "addr", addr)
		if err := app.Listen(addr); err != nil {
			l.Error("Server runtime failure", "error", err)
		}
	}()

	// 5. Graceful Shutdown Signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	<-quit
	l.Info("Shutting down server...")

	// 6. Final Resource Cleanup
	if err := app.Shutdown(); err != nil {
		l.Error("Fiber shutdown failed", "error", err)
	}

	// Using the new callable method from postgres package
	if err := postgres.Close(db); err != nil {
		l.Error("Database connection pool close failed", "error", err)
	}

	l.Info("Server stopped.")
}
