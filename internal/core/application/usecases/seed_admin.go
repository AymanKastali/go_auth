package usecases

import (
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
	"log/slog"
)

const seederTraceID = "system-seeder"

type seedAdminUseCase struct {
	userRepo ports.IUserRepository
	userSvc  ports.IUserService
	clockSvc ports.IClockService
}

func NewSeedAdminUseCase(
	userRepo ports.IUserRepository,
	userSvc ports.IUserService,
	clockSvc ports.IClockService,
) *seedAdminUseCase {
	return &seedAdminUseCase{
		userRepo: userRepo,
		userSvc:  userSvc,
		clockSvc: clockSvc,
	}
}

func (uc *seedAdminUseCase) Execute(l *slog.Logger, adminEmail, adminPassword string) error {
	l = l.With(slog.String("trace_id", seederTraceID))
	// 1. VO Conversion (Gatekeeping)
	emailVO, err := valueobjects.NewEmail(adminEmail)
	if err != nil {
		return apperr.Map(err)
	}

	rawPwd, err := valueobjects.NewRawPassword(adminPassword)
	if err != nil {
		return apperr.Map(err)
	}

	// 2. Check Existence
	// UseCase handles the flow: "If exists, do nothing"
	existing, err := uc.userRepo.GetByEmail(emailVO)
	if err != nil {
		return apperr.Map(err)
	}
	if existing != nil {
		l.Info("Admin user already exists, skipping seed", slog.String("email", adminEmail))
		return nil
	}

	now, _ := uc.clockSvc.Now()

	// 3. Delegation: Register via Domain Service
	// This handles: Password Policy, Hashing, and Default Role setup.
	admin, err := uc.userSvc.RegisterUser(emailVO, rawPwd, now)
	if err != nil {
		l.Error("Failed to register admin user through domain service", slog.Any("error", err))
		return apperr.Map(err)
	}

	// 4. Delegation: Assign Admin Role via Domain Service
	// We reuse the logic we built earlier for role management.
	if err := uc.userSvc.AssignRole(admin, "admin", now); err != nil {
		l.Error("Critical: failed to assign ADMIN role", slog.Any("error", err))
		return apperr.Map(err)
	}

	// 5. Persistence
	if err := uc.userRepo.Save(admin); err != nil {
		l.Error("Failed to persist seeded admin", slog.Any("error", err))
		return apperr.Map(err)
	}

	l.Info("Admin user successfully seeded",
		slog.String("email", adminEmail),
		slog.String("user_id", admin.ID().String()),
	)
	return nil
}
