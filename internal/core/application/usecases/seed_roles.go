package usecases

import (
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/domain/ports"
	"log/slog"
)

const rolesSeederTraceID = "system-roles-seeder"

type seedRolesUseCase struct {
	roleSvc  ports.IRoleService
	roleRepo ports.IRoleRepository
	clockSvc ports.IClockService
}

func NewSeedRolesUseCase(
	roleSvc ports.IRoleService,
	roleRepo ports.IRoleRepository,
	clockSvc ports.IClockService,
) *seedRolesUseCase {
	return &seedRolesUseCase{
		roleSvc:  roleSvc,
		roleRepo: roleRepo,
		clockSvc: clockSvc,
	}
}

func (uc *seedRolesUseCase) Execute(l *slog.Logger) error {
	l = l.With(slog.String("trace_id", rolesSeederTraceID))
	l.Info("Starting system roles seeding process")

	defaultRoles := []string{"admin", "user"}
	now, _ := uc.clockSvc.Now()

	for _, name := range defaultRoles {
		role, err := uc.roleSvc.EnsureRoleExists(name, now)
		if err != nil {
			l.Error("Failed to ensure role", slog.String("role", name), slog.Any("error", err))
			return apperr.Map(err)
		}

		// Check if the role was just created or already existed
		// If CreatedAt matches our 'now' timestamp, it's a new record.
		if role.CreatedAt().Equal(now) {
			if err := uc.roleRepo.Save(role); err != nil {
				return apperr.Map(err)
			}
			l.Info("System role successfully seeded",
				slog.String("role", name),
				slog.String("id", role.ID().String()),
			)
		} else {
			l.Debug("System role already exists, skipping", slog.String("role", name))
		}
	}

	l.Info("System roles seeding completed")
	return nil
}
