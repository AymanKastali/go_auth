package application

import (
	"context"
	"go_auth/internal/core/domain"
	"log/slog"
)

// --- Seed Super Admin Use Case ---
type seedSuperAdminUseCase struct {
	userRepo        domain.IUserRepository
	registrationSvc domain.IRegistrationService
	passwordMgr     domain.IPasswordManager
	idGen           domain.IIDGenerator
	clock           domain.IClock
}

func NewSeedSuperAdminUseCase(
	userRepo domain.IUserRepository,
	registrationSvc domain.IRegistrationService,
	passwordMgr domain.IPasswordManager,
	idGen domain.IIDGenerator,
	clock domain.IClock,
) ISeedSuperAdminUseCase {
	return &seedSuperAdminUseCase{
		userRepo:        userRepo,
		registrationSvc: registrationSvc,
		passwordMgr:     passwordMgr,
		idGen:           idGen,
		clock:           clock,
	}
}

func (uc *seedSuperAdminUseCase) Execute(ctx context.Context, cmd RegisterUserCommand) error {
	logger := GetLogger(ctx).With(
		slog.String("email", cmd.Email),
		slog.String("use_case", "SeedSuperAdmin"),
	)

	email, err := domain.NewEmail(cmd.Email)
	if err != nil {
		logger.Warn("invalid_email_format", slog.Any("error", err))
		return err
	}

	rawPassword, err := domain.NewRawPassword(cmd.Password)
	if err != nil {
		logger.Warn("invalid_password_format", slog.Any("error", err))
		return err
	}

	hashedPassword, err := uc.passwordMgr.ValidateAndHashNewPassword(rawPassword)
	if err != nil {
		logger.Warn("password_policy_violation", slog.Any("error", err))
		return err
	}

	uidVO, err := uc.idGen.GenerateUserID()
	if err != nil {
		logger.Error("id_generation_failed", slog.Any("error", err))
		return err
	}

	now := uc.clock.Now()

	user, err := uc.registrationSvc.RegisterNewSuperAdmin(ctx, uidVO, email, hashedPassword, now)
	if err != nil {
		logger.Warn("registration_domain_denied", slog.Any("error", err))
		return err
	}

	if err := uc.userRepo.Save(ctx, user); err != nil {
		logger.Error("database_save_failed", slog.Any("error", err))
		return err
	}

	logger.Info("super_admin_seeded_successfully",
		slog.String("user_id", user.ID().String()),
	)

	return nil
}
