package services

import (
	"go_auth/internal/adapters/seed"
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/interfaces"
	aports "go_auth/internal/core/application/ports"
	"go_auth/internal/core/domain/aggregates"
	dports "go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
	"log/slog"
)

type seedAdminService struct {
	userRepo       dports.UserRepositoryPort
	roleRepo       dports.RoleRepositoryPort
	passwordHasher aports.HashPasswordServicePort
	uuidGenerator  interfaces.IUUIDGeneratorService
	clock          interfaces.IClock
	cfg            *seed.SeederConfig
	logger         *slog.Logger
}

var _ aports.SeedAdminServicePort = (*seedAdminService)(nil)

func NewSeedAdminService(
	userRepo dports.UserRepositoryPort,
	roleRepo dports.RoleRepositoryPort,
	passwordHasher aports.HashPasswordServicePort,
	uuidGenerator interfaces.IUUIDGeneratorService,
	clock interfaces.IClock,
	seederConfig *seed.SeederConfig,
	logger *slog.Logger,
) aports.SeedAdminServicePort {
	return &seedAdminService{
		userRepo:       userRepo,
		roleRepo:       roleRepo,
		passwordHasher: passwordHasher,
		uuidGenerator:  uuidGenerator,
		clock:          clock,
		cfg:            seederConfig,
		logger:         logger,
	}
}

func (s *seedAdminService) SeedAdmin() error {
	adminEmail := s.cfg.AdminEmail()
	adminPass := s.cfg.AdminPassword()

	if adminEmail == "" || adminPass == "" {
		s.logger.Error("GA_ADMIN_EMAIL or GA_ADMIN_PASSWORD environment variables are not set")
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

	userID, err := s.uuidGenerator.NewUserID()
	if err != nil {
		s.logger.Error("Failed to generate user ID", "error", err)
		return apperr.NewInternalErr("failed to generate user id")
	}

	// Create admin user entity
	admin, err := aggregates.NewUser(
		userID,
		emailVO,
		pw,
		valueobjects.UserActive,
		[]valueobjects.RoleID{adminRole.ID()},
		s.clock.NowUTC(),
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
