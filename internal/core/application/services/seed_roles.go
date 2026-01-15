package services

import (
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
	"log/slog"
)

const rolesSeederTraceID = "system-roles-seeder"

type seedRolesService struct {
	roleRepo ports.IRoleRepository
	idSvc    ports.IIDService
	clock    ports.IClockService
	logger   *slog.Logger
}

func NewSeedRolesService(
	roleRepo ports.IRoleRepository,
	idSvc ports.IIDService,
	clock ports.IClockService,
	logger *slog.Logger,
) *seedRolesService {
	return &seedRolesService{
		roleRepo: roleRepo,
		idSvc:    idSvc,
		clock:    clock,
		logger:   logger,
	}
}

// SeedDefaultRoles ensures fundamental system roles exist.
func (s *seedRolesService) SeedDefaultRoles() error {
	// Standardizing to uppercase for strict matching
	defaultRoles := []string{"ADMIN", "USER"}

	for _, name := range defaultRoles {
		// 1. Existence Check
		existing, err := s.roleRepo.GetByName(name)
		if err != nil {
			// Maps technical DB errors to apperr.Internal (500)
			return apperr.Map(err, rolesSeederTraceID)
		}

		if existing != nil {
			s.logger.Debug("Role already exists, skipping", "role", name)
			continue
		}

		// 2. Identity Generation
		roleID := valueobjects.ReconstituteRoleID(s.idSvc.Generate())

		// 3. Aggregate Instantiation (Business Invariants)
		role, err := aggregates.NewRole(roleID, name, s.clock.Now().UTC())
		if err != nil {
			// Maps domain validation (e.g., invalid name) to apperr.Validation (422)
			return apperr.Map(err, rolesSeederTraceID)
		}

		// 4. Persistence
		if err := s.roleRepo.Save(role); err != nil {
			return apperr.Map(err, rolesSeederTraceID)
		}

		s.logger.Info("System role successfully seeded", "role", name)
	}

	return nil
}
