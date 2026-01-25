package main

import (
	"context"
	"go_auth/internal/adapters"
	"go_auth/internal/adapters/http/fiberapp"
	"go_auth/internal/adapters/persistence/postgres"
	"go_auth/internal/core/application"
	"go_auth/internal/core/domain"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
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
	defer postgres.Close(db)

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
	tokenProvider := adapters.NewAccessTokenProvider(
		cfg.JWT.Secret,
		cfg.JWT.AccessTTL,
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

	// Factories encapsulate the complex creation logic of entities
	userFactory := domain.NewUserFactory()
	sessionFactory := domain.NewSessionFactory()

	// 4. Domain Services
	// Satisfying the exact "want" arguments from the compiler
	identityGuard := domain.NewIdentityGuardService(clock)

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
	authService := domain.NewAuthenticationService(
		userRepo,
		passwordSvc,
		refreshTokenSvc, // Used as ITokenService for Refresh Tokens
		sessionFactory,
		sessionPolicy,
		clock,
		idGen,
	)

	// 5. Application Use Cases
	regUC := application.NewRegisterUseCase(userRepo, regService, passwordSvc)
	logUC := application.NewLoginUseCase(userRepo, authService, tokenProvider)
	refUC := application.NewRefreshTokenUseCase(userRepo, authService, tokenProvider)
	outUC := application.NewLogoutUseCase(userRepo, clock)
	valUC := application.NewValidateAccessUseCase(tokenProvider, userRepo, identityGuard)

	// 6. Transport Layer (Fiber v3)
	handler := fiberapp.NewAuthHandler(regUC, logUC, refUC, outUC, valUC)
	middleware := fiberapp.Protected(valUC)
	app := fiberapp.SetupApp(handler, middleware)

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
