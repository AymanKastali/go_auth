package services

import (
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/interfaces"
	aports "go_auth/internal/core/application/ports"
	"go_auth/internal/core/domain/aggregates"
	dports "go_auth/internal/core/domain/ports"
	"log/slog"
)

// Consistent trace ID for system-level background tasks
const rolesSeederTraceID = "system-roles-seeder"

type seedRolesService struct {
	roleRepo      dports.RoleRepositoryPort
	uuidGenerator interfaces.IUUIDGeneratorService
	clock         interfaces.IClock
	logger        *slog.Logger
}

var _ aports.SeedRolesServicePort = (*seedRolesService)(nil)

func NewSeedRolesService(
	roleRepo dports.RoleRepositoryPort,
	uuidGenerator interfaces.IUUIDGeneratorService,
	clock interfaces.IClock,
	logger *slog.Logger,
) aports.SeedRolesServicePort {
	return &seedRolesService{
		roleRepo:      roleRepo,
		uuidGenerator: uuidGenerator,
		clock:         clock,
		logger:        logger,
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
		roleID, err := s.uuidGenerator.NewRoleID()
		if err != nil {
			s.logger.Error("Failed to generate role ID", "error", err)
			return apperr.Internal("failed to generate unique role id", rolesSeederTraceID, err)
		}

		// 3. Aggregate Instantiation
		role, err := aggregates.NewRole(roleID, name, s.clock.NowUTC())
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
