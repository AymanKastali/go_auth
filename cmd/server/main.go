package main

import (
	"context"
	"go_auth/internal/adapters"
	"go_auth/internal/adapters/http/fiberapp"
	"go_auth/internal/adapters/persistence/postgres"
	"go_auth/internal/core/application"
	"go_auth/internal/core/domain"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	l := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	// 1. Load Centralized Config
	cfg, err := adapters.Load()
	if err != nil {
		log.Fatalf("CONFIG ERROR: %v", err)
	}

	// 2. Infrastructure Layer (Ports/Adapters)
	db, err := postgres.NewPostgresConnection(cfg.Database.URL)
	if err != nil {
		log.Fatalf("DATABASE CONNECTION FAILED: %v", err)
	}
	defer func() {
		if err := postgres.Close(db); err != nil {
			log.Printf("DATABASE CLOSE ERROR: %v", err)
		}
	}()

	log.Println("Running database migrations...")
	if err := postgres.Migrate(db); err != nil {
		log.Fatalf("MIGRATION FAILED: %v", err)
	}
	log.Println("Migrations completed successfully.")

	// Low-level technical ports
	userRepo := postgres.NewPostgresUserRepository(db)
	clock := adapters.NewClock()
	idGen := adapters.NewIDGenerator()
	passwordSvc := adapters.NewPasswordService(cfg.Password.BcryptCost)

	// Token provider (Stateless Access Tokens/JWT)
	jwtService := adapters.NewJWTService(
		cfg.JWT.Secret,
		cfg.JWT.Issuer,
		cfg.JWT.Audience,
	)
	refreshTokenSvc := adapters.NewTokenService()

	// 3. Domain Policies & Factories
	// We transform raw config into Domain-specific Value Objects/Policies
	passPolicy := domain.NewPasswordPolicy(
		cfg.PasswordPolicy.MinLength,
		cfg.PasswordPolicy.MaxLength,
		cfg.PasswordPolicy.RequireUpper,
		cfg.PasswordPolicy.RequireNumber,
		cfg.PasswordPolicy.RequireSpecial,
	)

	sessionPolicy := domain.NewSessionPolicy(
		cfg.SessionPolicy.Lifetime,
		cfg.SessionPolicy.MaxActive,
	)

	accessPolicy := domain.NewAccessPolicy(
		cfg.JWT.AccessTTL,
	)

	// Factories encapsulate the complex creation logic of entities
	userFactory := domain.NewUserFactory()
	sessionFactory := domain.NewSessionFactory()

	// 4. Domain Services

	regService := domain.NewUserRegistrationService(
		userRepo,
		passPolicy,
		passwordSvc,
		userFactory,
		idGen,
		clock,
	)

	// Note: AuthenticationService usually needs a way to hash/verify tokens
	// and manage sessions via a policy and factory.
	authenticateUserService := domain.NewAuthenticateUserService(
		userRepo,
		passwordSvc,
	)

	establishUserSessionSvc := domain.NewEstablishUserSessionService(
		sessionFactory, sessionPolicy, clock, idGen, refreshTokenSvc,
	)
	refreshUserSessionService := domain.NewRefreshUserSessionService(clock, refreshTokenSvc)

	accessGranterService := domain.NewAccessGrantor(
		jwtService,
		accessPolicy,
		clock,
	)

	// 5. Application Use Cases
	regUC := application.NewRegisterUseCase(userRepo, regService, passwordSvc)
	logUC := application.NewLoginUseCase(userRepo, authenticateUserService, establishUserSessionSvc, accessGranterService)
	refUC := application.NewRefreshTokenUseCase(userRepo, refreshUserSessionService, accessGranterService)
	outUC := application.NewLogoutUseCase(userRepo, clock)
	valUC := application.NewValidateAccessUseCase(jwtService, userRepo, clock)

	// Seeding SuperAdmin
	seedSAUC := application.NewSeedSuperAdminUseCase(userRepo, regService, passwordSvc)
	seedCtx, seedCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer seedCancel()
	seedCmd := application.RegisterUserCommand{
		Email:    cfg.Seed.AdminEmail,
		Password: cfg.Seed.AdminPassword,
	}
	log.Println("Seeding SuperAdmin...")
	if err := seedSAUC.Execute(seedCtx, seedCmd); err != nil {
		// We log but don't always terminate,
		// especially if the error is "User already exists"
		log.Printf("Seed skipped or failed: %v", err)
	} else {
		log.Println("SuperAdmin seeded successfully.")
	}

	// 6. Transport Layer (Fiber v3)
	handler := fiberapp.NewAuthHandler(regUC, logUC, refUC, outUC, valUC)
	middleware := fiberapp.Protected(valUC)
	app := fiberapp.SetupApp(handler, middleware, l)

	// 7. Graceful Shutdown Orchestration
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("%s starting on port :%s (Env: %s)", cfg.App.Name, cfg.HTTP.Port, cfg.App.Env)
		if err := app.Listen(":" + cfg.HTTP.Port); err != nil {
			log.Printf("Server failure: %v", err)
		}
	}()

	<-sigChan
	log.Println("Shutting down gracefully...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := app.ShutdownWithContext(ctx); err != nil {
		log.Printf("Fiber shutdown error: %v", err)
	}

	log.Println("Server stopped.")
}
