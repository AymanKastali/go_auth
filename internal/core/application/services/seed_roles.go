package services

import (
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/interfaces"
	aports "go_auth/internal/core/application/ports"
	"go_auth/internal/core/domain/aggregates"
	dports "go_auth/internal/core/domain/ports"
	"log/slog"
)

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
		// 1. Check existence (Internal Intent)
		exists, err := s.roleRepo.GetByName(name)
		if err != nil {
			s.logger.Error("Failed to check role existence", "role", name, "error", err)
			return apperr.Internal(err)
		}
		if exists != nil {
			continue
		}

		// 2. Identity Generation (Internal Intent)
		roleID, err := s.uuidGenerator.NewRoleID()
		if err != nil {
			s.logger.Error("Failed to generate role ID", "error", err)
			return apperr.Internal(err)
		}

		// 3. Aggregate Instantiation (Validation/Logic Intent)
		role, err := aggregates.NewRole(roleID, name, s.clock.NowUTC())
		if err != nil {
			s.logger.Error("Failed to create role entity", "role", name, "error", err)
			// Domain invariant failures are wrapped as Validation
			return apperr.Validation(err)
		}

		// 4. Persistence (Internal Intent)
		if err := s.roleRepo.Save(role); err != nil {
			s.logger.Error("Failed to save role", "role", name, "error", err)
			return apperr.Internal(err)
		}

		s.logger.Info("Role successfully seeded", "role", name)
	}

	return nil
}
