package services

import (
	"errors"
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

	// 1. Config Check (Internal Intent)
	if adminEmail == "" || adminPass == "" {
		s.logger.Error("GA_ADMIN_EMAIL or GA_ADMIN_PASSWORD environment variables are not set")
		return apperr.Internal(errors.New("seeder configuration missing"))
	}

	// 2. Value Object Creation (Validation Intent)
	emailVO, err := valueobjects.NewEmail(adminEmail)
	if err != nil {
		s.logger.Error("Failed to create Email value object", "error", err)
		return apperr.Validation(err)
	}

	// 3. Existence Check
	existing, err := s.userRepo.GetByEmail(emailVO)
	if err != nil {
		s.logger.Error("Failed to check admin existence", "error", err)
		return apperr.Internal(err)
	}
	if existing != nil {
		s.logger.Info("Admin user already exists, skipping seeding", "email", adminEmail)
		return nil
	}

	// 4. Cryptography (Internal Intent)
	hash, err := s.passwordHasher.Hash(adminPass)
	if err != nil {
		s.logger.Error("Failed to hash admin password", "error", err)
		return apperr.Internal(err)
	}

	pw, err := valueobjects.NewHashedPassword(hash)
	if err != nil {
		return apperr.Validation(err)
	}

	// 5. Dependency Check (NotFound Intent)
	adminRole, err := s.roleRepo.GetByName("admin")
	if err != nil {
		s.logger.Error("Failed to fetch admin role", "error", err)
		return apperr.Internal(err)
	}
	if adminRole == nil {
		s.logger.Error("admin role does not exist")
		return apperr.NotFound(nil)
	}

	// 6. Identity Generation
	userID, err := s.uuidGenerator.NewUserID()
	if err != nil {
		return apperr.Internal(err)
	}

	// 7. Aggregate Instantiation (Validation/Logic Intent)
	admin, err := aggregates.NewUser(
		userID,
		emailVO,
		pw,
		valueobjects.UserActive,
		[]valueobjects.RoleID{adminRole.ID()},
		s.clock.NowUTC(),
	)
	if err != nil {
		// Domain invariants check
		return apperr.Validation(err)
	}

	// 8. Persistence
	if err := s.userRepo.Save(admin); err != nil {
		return apperr.Internal(err)
	}

	s.logger.Info("Admin user successfully seeded", "email", adminEmail)
	return nil
}
