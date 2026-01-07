package services

import (
	"go_auth/internal/adapters/config"
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/ports/repositories"
	"go_auth/internal/core/application/ports/security"
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/valueobjects"
	"log/slog"
	"time"
)

type SeedAdminService struct {
	userRepo       repositories.UserRepositoryPort
	roleRepo       repositories.RoleRepositoryPort
	passwordHasher security.HashPasswordPort
	cfg            *config.SeederConfig
	logger         *slog.Logger
}

func NewSeedAdminService(
	userRepo repositories.UserRepositoryPort,
	roleRepo repositories.RoleRepositoryPort,
	passwordHasher security.HashPasswordPort,
	seederConfig *config.SeederConfig,
	logger *slog.Logger,
) *SeedAdminService {
	return &SeedAdminService{
		userRepo:       userRepo,
		roleRepo:       roleRepo,
		passwordHasher: passwordHasher,
		cfg:            seederConfig,
		logger:         logger,
	}
}

func (s *SeedAdminService) SeedAdmin() error {
	adminEmail := s.cfg.AdminEmail
	adminPass := s.cfg.AdminPassword

	if adminEmail == "" || adminPass == "" {
		s.logger.Error("ADMIN_EMAIL or ADMIN_PASSWORD environment variables are not set")
		return apperr.NewInternalErr("seeder configuration missing")
	}

	emailVO, err := valueobjects.NewEmail(adminEmail)
	if err != nil {
		s.logger.Error("Failed to create Email value object", "error", err)
		return apperr.MapDomainErr(err)
	}

	// Check if admin exists
	existing, err := s.userRepo.GetByEmail(emailVO)
	if err != nil {
		s.logger.Error("Failed to check admin existence", "error", err)
		return apperr.NewInternalErr("failed to check admin existence")
	}
	if existing != nil {
		s.logger.Info("Admin user already exists, skipping seeding", "email", adminEmail)
		return nil
	}

	// Hash password
	hash, err := s.passwordHasher.Hash(adminPass)
	if err != nil {
		s.logger.Error("Failed to hash admin password", "error", err)
		return apperr.NewInternalErr("password hashing failed")
	}
	pw := valueobjects.NewHashedPassword(hash)

	// Fetch admin role
	adminRole, err := s.roleRepo.GetByName("admin")
	if err != nil {
		s.logger.Error("Failed to fetch admin role", "error", err)
		return apperr.NewInternalErr("failed to fetch admin role")
	}
	if adminRole == nil {
		s.logger.Error("admin role does not exist, cannot seed admin user")
		return apperr.NewInternalErr("admin role missing")
	}

	// Create admin user entity
	admin, err := aggregates.NewUser(
		valueobjects.NewUserID(),
		emailVO,
		pw,
		valueobjects.UserActive,
		[]valueobjects.RoleID{adminRole.ID()},
		time.Now().UTC(),
	)
	if err != nil {
		s.logger.Error("Failed to create admin entity", "error", err)
		return apperr.MapDomainErr(err)
	}

	// Save admin
	if err := s.userRepo.Save(admin); err != nil {
		s.logger.Error("Failed to save admin to repository", "error", err)
		return apperr.NewInternalErr("failed to save admin user")
	}

	s.logger.Info("Admin user successfully seeded", "email", adminEmail)
	return nil
}
