package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"go_auth/internal/adapters"
	"go_auth/internal/adapters/http/fiberapp"
	"go_auth/internal/adapters/persistence/postgres"
	"go_auth/internal/core/application"
	"go_auth/internal/core/domain"
)

func main() {
	// 1. Load Centralized Config
	cfg, err := adapters.Load()
	if err != nil {
		// Fallback to a basic logger if config fails
		slog.Error("failed_to_load_config", slog.Any("error", err))
		os.Exit(1)
	}

	// 2. Setup Structured Logger
	var programLevel slog.Level
	switch strings.ToLower(cfg.App.LogLevel) {
	case "debug":
		programLevel = slog.LevelDebug
	case "warn":
		programLevel = slog.LevelWarn
	case "error":
		programLevel = slog.LevelError
	default:
		programLevel = slog.LevelInfo
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true,
		Level:     programLevel,
	}))
	slog.SetDefault(logger)

	// 3. Infrastructure Layer (Ports/Adapters)
	db, err := postgres.NewPostgresConnection(cfg.Database.URL)
	if err != nil {
		logger.Error("database_connection_failed", slog.Any("error", err))
		os.Exit(1)
	}
	defer func() {
		if err := postgres.Close(db); err != nil {
			logger.Error("database_close_error", slog.Any("error", err))
		}
	}()

	logger.Info("running_database_migrations")
	if err := postgres.Migrate(db); err != nil {
		logger.Error("migration_failed", slog.Any("error", err))
		os.Exit(1)
	}
	logger.Info("migrations_completed_successfully")

	// Low-level technical ports
	userRepo := postgres.NewPostgresUserRepository(db)
	clock := adapters.NewClock()
	idGen := adapters.NewIDGenerator()
	passwordSvc := adapters.NewPasswordService(cfg.Password.BcryptCost)
	jwtService := adapters.NewJWTService(cfg.JWT.Secret, cfg.JWT.Issuer, cfg.JWT.Audience)
	refreshTokenSvc := adapters.NewTokenService()

	// 4. Domain Policies & Factories
	passPolicy := domain.NewPasswordPolicy(
		cfg.PasswordPolicy.MinLength,
		cfg.PasswordPolicy.MaxLength,
		cfg.PasswordPolicy.RequireUpper,
		cfg.PasswordPolicy.RequireNumber,
		cfg.PasswordPolicy.RequireSpecial,
	)
	sessionPolicy := domain.NewSessionPolicy(cfg.SessionPolicy.Lifetime, cfg.SessionPolicy.MaxActive)
	accessPolicy := domain.NewAccessPolicy(cfg.JWT.AccessTTL)
	userFactory := domain.NewUserFactory()
	sessionFactory := domain.NewSessionFactory()

	// 5. Domain Services
	regService := domain.NewRegisterUserService(userRepo, passPolicy, passwordSvc, userFactory, idGen, clock)
	authService := domain.NewAuthenticateUserService(userRepo, passwordSvc)
	sessionService := domain.NewEstablishUserSessionService(sessionFactory, sessionPolicy, clock, idGen, refreshTokenSvc)
	refreshService := domain.NewRefreshSessionService(userRepo, refreshTokenSvc, clock)
	accessGranter := domain.NewAccessGrantor(jwtService, accessPolicy, clock)

	// 6. Application Use Cases
	regUC := application.NewRegisterUseCase(userRepo, regService)
	logUC := application.NewLoginUseCase(userRepo, authService, sessionService, accessGranter)
	refUC := application.NewRefreshTokenUseCase(userRepo, refreshService, accessGranter)
	outUC := application.NewLogoutUseCase(userRepo, clock)
	valUC := application.NewValidateAccessUseCase(jwtService, userRepo, clock)

	// 7. Seeding SuperAdmin
	logger.Info("seeding_super_admin_attempt", slog.String("email", cfg.Seed.AdminEmail))
	seedSAUC := application.NewSeedSuperAdminUseCase(userRepo, regService)
	seedCtx, seedCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer seedCancel()

	if err := seedSAUC.Execute(seedCtx, application.RegisterUserCommand{
		Email:    cfg.Seed.AdminEmail,
		Password: cfg.Seed.AdminPassword,
	}); err != nil {
		// Log as Warn since "User already exists" is a common non-fatal scenario
		logger.Warn("seed_skipped_or_failed", slog.Any("error", err))
	} else {
		logger.Info("super_admin_seeded_successfully")
	}

	// 8. Transport Layer (Fiber v3)
	handler := fiberapp.NewAuthHandler(regUC, logUC, refUC, outUC, valUC)
	middleware := fiberapp.Protected(valUC)
	app := fiberapp.SetupApp(handler, middleware, logger)

	// 9. Graceful Shutdown Orchestration
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		logger.Info("server_starting",
			slog.String("app_name", cfg.App.Name),
			slog.String("port", cfg.HTTP.Port),
			slog.String("env", cfg.App.Env),
		)
		if err := app.Listen(":" + cfg.HTTP.Port); err != nil {
			logger.Error("server_failure", slog.Any("error", err))
		}
	}()

	<-sigChan
	logger.Info("shutting_down_gracefully")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := app.ShutdownWithContext(ctx); err != nil {
		logger.Error("fiber_shutdown_error", slog.Any("error", err))
	}

	logger.Info("server_stopped_cleanly")
}
