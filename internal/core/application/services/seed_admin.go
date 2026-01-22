package services

import (
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
	"log/slog"
)

const seederTraceID = "system-seeder"

type seedAdminSvc struct {
	userRepo       ports.IUserRepository
	roleRepo       ports.IRoleRepository
	passwordHasher ports.IPasswordHasherService
	idSvc          ports.IIDService
	clockSvc       ports.IClockService
	adminEmail     string
	adminPassword  string
	l              *slog.Logger
}

func NewSeedAdminSvc(
	userRepo ports.IUserRepository,
	roleRepo ports.IRoleRepository,
	passwordHasher ports.IPasswordHasherService,
	idSvc ports.IIDService,
	clockSvc ports.IClockService,
	adminEmail string,
	adminPassword string,
	l *slog.Logger,
) *seedAdminSvc {
	return &seedAdminSvc{
		userRepo:       userRepo,
		roleRepo:       roleRepo,
		passwordHasher: passwordHasher,
		idSvc:          idSvc,
		clockSvc:       clockSvc,
		adminEmail:     adminEmail,
		adminPassword:  adminPassword,
		l:              l,
	}
}

func (s *seedAdminSvc) SeedAdmin() error {
	adminEmail := s.adminEmail
	adminPass := s.adminPassword

	l := s.l.With(slog.String("trace_id", seederTraceID))

	l.Info("Starting admin user seeding process")

	if adminEmail == "" || adminPass == "" {
		l.Warn("Admin seeding skipped: missing environment configuration")
		return nil
	}

	emailVO, err := valueobjects.NewEmail(adminEmail)
	if err != nil {
		l.Error("Invalid admin email in configuration",
			slog.String("email", adminEmail),
			slog.Any("error", err),
		)
		return apperr.Map(err)
	}

	existing, err := s.userRepo.GetByEmail(emailVO)
	if err != nil {
		l.Error("Database error checking admin existence", slog.Any("error", err))
		return apperr.Map(err)
	}
	if existing != nil {
		l.Info("Admin user already exists, skipping seed", slog.String("email", adminEmail))
		return nil
	}

	adminRole, err := s.roleRepo.GetByName("admin")
	if err != nil {
		l.Error("Database error retrieving ADMIN role", slog.Any("error", err))
		return apperr.Map(err)
	}
	if adminRole == nil {
		l.Error("CRITICAL: Data integrity violation - ADMIN role must exist before seeding")
		return apperr.Internal("required system roles missing", nil)
	}

	rawPwd, err := valueobjects.NewRawPassword(adminPass)
	if err != nil {
		return apperr.Map(err)
	}

	hashedPwd, err := s.passwordHasher.Hash(rawPwd)
	if err != nil {
		l.Error("Cryptography failure during admin seeding", slog.Any("error", err))
		return apperr.Internal("cryptography failure during seeding", err)
	}

	userID, err := valueobjects.NewUserID(s.idSvc.Generate())
	if err != nil {
		return apperr.Map(err)
	}
	now, err := s.clockSvc.Now()
	if err != nil {
		return apperr.Map(err)
	}

	admin, err := aggregates.NewUser(
		userID,
		emailVO,
		hashedPwd,
		valueobjects.UserActive,
		[]valueobjects.RoleID{adminRole.ID()},
		now,
	)
	if err != nil {
		return apperr.Map(err)
	}

	if err := s.userRepo.Create(admin); err != nil {
		l.Error("Database error creating admin user", slog.Any("error", err))
		return apperr.Map(err)
	}

	l.Info("Admin user successfully seeded",
		slog.String("email", adminEmail),
		slog.String("user_id", userID.String()),
	)
	return nil
}
