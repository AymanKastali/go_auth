package services

import (
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
	"log/slog"
)

const rolesSeederTraceID = "system-roles-seeder"

type seedRolesSvc struct {
	roleRepo ports.IRoleRepository
	idSvc    ports.IIDService
	clockSvc ports.IClockService
	l        *slog.Logger
}

func NewSeedRolesSvc(
	roleRepo ports.IRoleRepository,
	idSvc ports.IIDService,
	clockSvc ports.IClockService,
	l *slog.Logger,
) *seedRolesSvc {
	return &seedRolesSvc{
		roleRepo: roleRepo,
		idSvc:    idSvc,
		clockSvc: clockSvc,
		l:        l,
	}
}

func (s *seedRolesSvc) SeedDefaultRoles() error {
	defaultRoles := []string{"admin", "user"}
	l := s.l.With(slog.String("trace_id", rolesSeederTraceID))
	now, err := s.clockSvc.Now()
	if err != nil {
		return apperr.Map(err)
	}

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

		roleID, err := valueobjects.NewRoleID(s.idSvc.Generate())
		if err != nil {
			return apperr.Map(err)
		}

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
