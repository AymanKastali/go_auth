package services

import (
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/interfaces"
	aports "go_auth/internal/core/application/ports"
	"go_auth/internal/core/domain/aggregates"
	dports "go_auth/internal/core/domain/ports"
	"log/slog"
	"time"
)

type seedRolesService struct {
	roleRepo      dports.RoleRepositoryPort
	uuidGenerator interfaces.IUUIDGeneratorService
	logger        *slog.Logger
}

var _ aports.SeedRolesServicePort = (*seedRolesService)(nil)

func NewSeedRolesService(
	roleRepo dports.RoleRepositoryPort,
	uuidGenerator interfaces.IUUIDGeneratorService,
	logger *slog.Logger,
) aports.SeedRolesServicePort {
	return &seedRolesService{
		roleRepo:      roleRepo,
		uuidGenerator: uuidGenerator,
		logger:        logger,
	}
}

// SeedDefaultRoles creates user, admin, STAFF roles if they don't exist
func (s *seedRolesService) SeedDefaultRoles() error {
	defaultRoles := []string{"admin", "user"}

	for _, name := range defaultRoles {
		exists, err := s.roleRepo.GetByName(name)
		if err != nil {
			s.logger.Error("Failed to check role existence", "role", name, "error", err)
			return apperr.NewInternalErr("failed to check role existence")
		}
		if exists != nil {
			continue // already exists
		}
		roleID, err := s.uuidGenerator.NewRoleID()
		if err != nil {
			s.logger.Error("Failed to generate role ID", "error", err)
			return apperr.NewInternalErr("failed to generate role id")
		}

		role, err := aggregates.NewRole(roleID, name, time.Now().UTC())
		if err != nil {
			s.logger.Error("Failed to create role entity", "role", name, "error", err)
			return apperr.MapDomainErr(err)
		}

		if err := s.roleRepo.Save(role); err != nil {
			s.logger.Error("Failed to save role", "role", name, "error", err)
			return apperr.NewInternalErr("failed to save role")
		}

		s.logger.Info("Role successfully seeded", "role", name)
	}

	return nil
}
