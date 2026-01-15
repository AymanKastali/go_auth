package services

import (
	"go_auth/internal/adapters/seed"
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
	"log/slog"
)

const seederTraceID = "system-seeder"

type seedAdminService struct {
	userRepo       ports.IUserRepository
	roleRepo       ports.IRoleRepository
	passwordHasher ports.IPasswordService
	idSvc          ports.IIDService
	clock          ports.IClockService
	cfg            *seed.SeederConfig
	logger         *slog.Logger
}

func NewSeedAdminService(
	userRepo ports.IUserRepository,
	roleRepo ports.IRoleRepository,
	passwordHasher ports.IPasswordService,
	idSvc ports.IIDService,
	clock ports.IClockService,
	seederConfig *seed.SeederConfig,
	logger *slog.Logger,
) *seedAdminService {
	return &seedAdminService{
		userRepo:       userRepo,
		roleRepo:       roleRepo,
		passwordHasher: passwordHasher,
		idSvc:          idSvc,
		clock:          clock,
		cfg:            seederConfig,
		logger:         logger,
	}
}

func (s *seedAdminService) SeedAdmin() error {
	adminEmail := s.cfg.AdminEmail()
	adminPass := s.cfg.AdminPassword()

	// 1. Config Check
	if adminEmail == "" || adminPass == "" {
		s.logger.Error("GA_ADMIN_EMAIL or GA_ADMIN_PASSWORD environment variables are not set")
		return apperr.Internal("seeder configuration missing", seederTraceID, nil)
	}

	// 2. Value Object Creation
	emailVO, err := valueobjects.NewEmail(adminEmail)
	if err != nil {
		s.logger.Error("Failed to create Email value object", "error", err)
		return apperr.Invalid("invalid admin email in config", seederTraceID, err)
	}

	// 3. Existence Check
	existing, err := s.userRepo.GetByEmail(emailVO)
	if err != nil {
		s.logger.Error("Failed to check admin existence", "error", err)
		return apperr.FromDomain(err, seederTraceID)
	}
	if existing != nil {
		s.logger.Info("Admin user already exists, skipping seeding", "email", adminEmail)
		return nil
	}

	// 4. Cryptography
	hash, err := s.passwordHasher.Hash(adminPass)
	if err != nil {
		s.logger.Error("Failed to hash admin password", "error", err)
		return apperr.Internal("cryptography failure during seeding", seederTraceID, err)
	}

	pw, err := valueobjects.NewHashedPassword(hash)
	if err != nil {
		return apperr.FromDomain(err, seederTraceID)
	}

	// 5. Role Dependency Check
	adminRole, err := s.roleRepo.GetByName("admin")
	if err != nil {
		s.logger.Error("Failed to fetch admin role", "error", err)
		return apperr.FromDomain(err, seederTraceID)
	}
	if adminRole == nil {
		s.logger.Error("admin role does not exist")
		return apperr.NotFound("required admin role missing from database", seederTraceID, nil)
	}

	// 6. Identity Generation
	userID, err := valueobjects.NewUserID(s.idSvc.Generate())
	if err != nil {
		return apperr.Internal("failed to generate admin uuid", seederTraceID, err)
	}

	// 7. Aggregate Instantiation
	admin, err := aggregates.NewUser(
		userID,
		emailVO,
		pw,
		valueobjects.UserActive,
		[]valueobjects.RoleID{adminRole.ID()},
		s.clock.Now().UTC(),
	)
	if err != nil {
		return apperr.FromDomain(err, seederTraceID)
	}

	// 8. Persistence
	if err := s.userRepo.Create(admin); err != nil {
		return apperr.FromDomain(err, seederTraceID)
	}

	s.logger.Info("Admin user successfully seeded", "email", adminEmail)
	return nil
}
