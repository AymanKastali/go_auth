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
	// 1. Initialize Logger (Using slog for consistency with Use Cases)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// 2. Load Database Configuration
	dbCfg, err := postgres.NewPostgresConfig()
	if err != nil {
		slog.Error("Failed to load database configuration", "error", err)
		os.Exit(1)
	}

	// 3. Establish Database Connection
	db, err := postgres.NewPostgresConnection(dbCfg)
	if err != nil {
		if pgerr.IsUnavailable(err) {
			slog.Error("CRITICAL: Database is unavailable. Check network or credentials.", "error", err)
		}
		slog.Error("Database connection failed", "error", err)
		os.Exit(1)
	}

	// 4. Run Migrations
	if err := postgres.AutoMigrate(db); err != nil {
		slog.Error("Database migration failed", "error", err)
		os.Exit(1)
	}

	// 5. Initialize Dependencies (Dependency Injection)
	deps, err := fiber.InitDeps(db)
	if err != nil {
		slog.Error("Failed to initialize application dependencies", "error", err)
		os.Exit(1)
	}

	// 6. Load Fiber Configuration
	fiberCfg, err := fiber.NewFiberConfig()
	if err != nil {
		slog.Error("Failed to load fiber configuration", "error", err)
		os.Exit(1)
	}

	// 7. Initialize Fiber App
	app := fiber.NewFiberApp(deps, fiberCfg, logger)

	// 8. Graceful Shutdown Implementation
	// This ensures the server stops correctly on Ctrl+C or Docker stop
	go func() {
		slog.Info("Server is starting", "port", fiberCfg.Port())
		if err := app.Listen(fiberCfg.ListenAddr()); err != nil {
			slog.Error("Server runtime failure", "error", err)
		}
	}()

	// Listen for shutdown signals
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	<-quit
	slog.Info("Shutting down server...")

	if err := app.Shutdown(); err != nil {
		slog.Error("Graceful shutdown failed", "error", err)
	}

	slog.Info("Server stopped.")
}
