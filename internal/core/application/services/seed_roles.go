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

func (s *seedRolesService) SeedDefaultRoles() error {
	defaultRoles := []string{"ADMIN", "USER"}
	l := s.logger.With(slog.String("trace_id", rolesSeederTraceID))
	now := s.clock.Now().UTC()

	l.Info("Starting system roles seeding process")

	for _, name := range defaultRoles {
		existing, err := s.roleRepo.GetByName(name)
		if err != nil {
			l.Error("Database error checking role existence",
				slog.String("role", name),
				slog.Any("error", err),
			)
			return apperr.Map(err)
		}

		if existing != nil {
			l.Debug("System role already exists, skipping", slog.String("role", name))
			continue
		}

		roleID := valueobjects.ReconstituteRoleID(s.idSvc.Generate())

		role, err := aggregates.NewRole(roleID, name, now)
		if err != nil {
			l.Error("Domain validation failed during role instantiation",
				slog.String("role", name),
				slog.Any("error", err),
			)
			return apperr.Map(err)
		}

		if err := s.roleRepo.Save(role); err != nil {
			l.Error("Database error persisting system role",
				slog.String("role", name),
				slog.Any("error", err),
			)
			return apperr.Map(err)
		}

		l.Info("System role successfully seeded",
			slog.String("role", name),
			slog.String("role_id", roleID.Value()),
		)
	}

	return nil
}
