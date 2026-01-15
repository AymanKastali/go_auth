package services

import (
	"go_auth/internal/core/application/apperr"
	aports "go_auth/internal/core/application/ports"
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
	cfg            aports.ISeederConfig
	logger         *slog.Logger
}

func NewSeedAdminService(
	userRepo ports.IUserRepository,
	roleRepo ports.IRoleRepository,
	passwordHasher ports.IPasswordService,
	idSvc ports.IIDService,
	clock ports.IClockService,
	seederConfig aports.ISeederConfig,
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
		s.logger.Error("seeding skipped: environment variables not set")
		return apperr.Internal("seeder configuration missing", seederTraceID, nil)
	}

	// 2. Value Object Creation
	emailVO, err := valueobjects.NewEmail(adminEmail)
	if err != nil {
		return apperr.Map(err, seederTraceID)
	}

	// 3. Existence Check
	existing, err := s.userRepo.GetByEmail(emailVO)
	if err != nil {
		return apperr.Map(err, seederTraceID)
	}
	if existing != nil {
		s.logger.Info("admin user already exists, skipping", "email", adminEmail)
		return nil
	}

	// 4. Role Dependency Check (Strict)
	// We use "ADMIN" standardized uppercase to match typical strict naming
	adminRole, err := s.roleRepo.GetByName("ADMIN")
	if err != nil {
		return apperr.Map(err, seederTraceID)
	}
	if adminRole == nil {
		s.logger.Error("DATA INTEGRITY VIOLATION: ADMIN role must exist before seeding admin user")
		return apperr.Internal("required system roles missing", seederTraceID, nil)
	}

	// 5. Cryptography
	hash, err := s.passwordHasher.Hash(adminPass)
	if err != nil {
		return apperr.Internal("cryptography failure during seeding", seederTraceID, err)
	}

	pw, err := valueobjects.NewHashedPassword(hash)
	if err != nil {
		return apperr.Map(err, seederTraceID)
	}

	// 6. Identity & Aggregate
	userID := valueobjects.ReconstituteUserID(s.idSvc.Generate())

	admin, err := aggregates.NewUser(
		userID,
		emailVO,
		pw,
		valueobjects.UserActive,
		[]valueobjects.RoleID{adminRole.ID()},
		s.clock.Now().UTC(),
	)
	if err != nil {
		return apperr.Map(err, seederTraceID)
	}

	// 7. Persistence
	if err := s.userRepo.Create(admin); err != nil {
		return apperr.Map(err, seederTraceID)
	}

	s.logger.Info("admin user successfully seeded", "email", adminEmail)
	return nil
}
