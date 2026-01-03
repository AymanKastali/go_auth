package services

import (
	"go_auth/internal/adapters/config"
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/ports/security"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/ports/repositories"
	"go_auth/internal/core/domain/valueobjects"
	"log/slog"
	"time"
)

type SeedAdminService struct {
	userRepo       repositories.UserRepositoryPort
	passwordHasher security.HashPasswordPort
	cfg            *config.SeederConfig
	logger         *slog.Logger
}

func NewSeedAdminService(
	repo repositories.UserRepositoryPort,
	passwordHasher security.HashPasswordPort,
	seederConfig *config.SeederConfig,
	logger *slog.Logger,
) *SeedAdminService {
	return &SeedAdminService{
		userRepo:       repo,
		passwordHasher: passwordHasher,
		cfg:            seederConfig,
		logger:         logger,
	}
}

func (s *SeedAdminService) SeedAdmin() error {
	adminEmail := s.cfg.AdminEmail
	adminPass := s.cfg.AdminPassword

	// Validation: Ensure env variables aren't empty
	if adminEmail == "" || adminPass == "" {
		s.logger.Error("ADMIN_EMAIL or ADMIN_PASSWORD environment variables are not set")
		// FIX: Use factory method
		return apperr.NewInternal("seeder configuration missing")
	}

	// 1. Check if admin already exists
	emailVO, err := valueobjects.NewEmail(adminEmail)
	if err != nil {
		s.logger.Error("Failed to create Email value object", "error", err)
		// FIX: Use MapDomain for Domain Rule violations
		return apperr.MapDomain(err)
	}

	exists, err := s.userRepo.GetByEmail(emailVO)
	if err != nil {
		s.logger.Error("Failed to check if admin exists", "error", err)
		return apperr.NewInternal("failed to check admin existence")
	}
	if exists != nil {
		s.logger.Info("Admin user already exists, skipping seeding", "email", adminEmail)
		return nil
	}

	// 2. Hash the password from .env
	hash, err := s.passwordHasher.Hash(adminPass)
	if err != nil {
		s.logger.Error("Failed to hash admin password", "error", err)
		return apperr.NewInternal("password hashing failed")
	}
	pw := valueobjects.NewHashedPassword(hash)

	// 3. Create the Admin Entity via Factory
	admin, err := entities.NewUser(
		valueobjects.NewUserID(),
		emailVO,
		pw,
		valueobjects.UserActive,
		[]valueobjects.Role{valueobjects.RoleAdmin},
		time.Now().UTC(),
	)
	if err != nil {
		s.logger.Error("Failed to create admin entity", "error", err)
		return apperr.MapDomain(err)
	}

	// 4. Save to Repository
	if err := s.userRepo.Save(admin); err != nil {
		s.logger.Error("Failed to save admin to repository", "error", err)
		return apperr.NewInternal("failed to save admin user")
	}

	s.logger.Info("Admin user successfully seeded", "email", adminEmail)
	return nil
}
