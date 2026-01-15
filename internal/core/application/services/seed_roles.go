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

// SeedDefaultRoles creates user, admin roles if they don't exist
func (s *seedRolesService) SeedDefaultRoles() error {
	defaultRoles := []string{"admin", "user"}

	for _, name := range defaultRoles {
		// 1. Check existence
		exists, err := s.roleRepo.GetByName(name)
		if err != nil {
			s.logger.Error("Failed to check role existence", "role", name, "error", err)
			// Wrap infrastructure/repo errors
			return apperr.FromDomain(err, rolesSeederTraceID)
		}
		if exists != nil {
			continue
		}

		// 2. Identity Generation
		roleID, err := valueobjects.NewRoleID(s.idSvc.Generate())
		if err != nil {
			s.logger.Error("Failed to generate role ID", "error", err)
			return apperr.Internal("failed to generate unique role id", rolesSeederTraceID, err)
		}

		// 3. Aggregate Instantiation
		role, err := aggregates.NewRole(roleID, name, s.clock.Now().UTC())
		if err != nil {
			s.logger.Error("Failed to create role entity", "role", name, "error", err)
			// Map domain validation failures (e.g., name too short) to AppError
			return apperr.FromDomain(err, rolesSeederTraceID)
		}

		// 4. Persistence
		if err := s.roleRepo.Save(role); err != nil {
			s.logger.Error("Failed to save role", "role", name, "error", err)
			return apperr.FromDomain(err, rolesSeederTraceID)
		}

		s.logger.Info("Role successfully seeded", "role", name)
	}

	return nil
}
