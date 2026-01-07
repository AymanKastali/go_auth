package services

import (
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/ports"
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/valueobjects"
	"log/slog"
	"time"
)

type seedRolesService struct {
	roleRepo ports.RoleRepositoryPort
	logger   *slog.Logger
}

var _ ports.SeedRolesServicePort = (*seedRolesService)(nil)

func NewSeedRolesService(
	roleRepo ports.RoleRepositoryPort,
	logger *slog.Logger,
) ports.SeedRolesServicePort {
	return &seedRolesService{
		roleRepo: roleRepo,
		logger:   logger,
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

		role, err := aggregates.NewRole(valueobjects.NewRoleID(), name, time.Now().UTC())
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
