package command

import (
	"context"
	"log/slog"

	"go_auth/internal/application"
	"go_auth/internal/domain"
)

type ISeedSuperAdminHandler interface {
	Handle(ctx context.Context, cmd RegisterUserCommand) error
}

type seedSuperAdminHandler struct {
	userRepo        domain.IUserRepository
	registrationSvc domain.IRegistrationService
	passwordMgr     domain.IPasswordManager
	idGen           domain.IIDGenerator
	clock           domain.IClock
	dispatcher      IEventDispatcher
}

func NewSeedSuperAdminHandler(
	userRepo domain.IUserRepository,
	registrationSvc domain.IRegistrationService,
	passwordMgr domain.IPasswordManager,
	idGen domain.IIDGenerator,
	clock domain.IClock,
	dispatcher IEventDispatcher,
) ISeedSuperAdminHandler {
	return &seedSuperAdminHandler{
		userRepo:        userRepo,
		registrationSvc: registrationSvc,
		passwordMgr:     passwordMgr,
		idGen:           idGen,
		clock:           clock,
		dispatcher:      dispatcher,
	}
}

func (h *seedSuperAdminHandler) Handle(ctx context.Context, cmd RegisterUserCommand) error {
	logger := application.GetLogger(ctx).With(
		slog.String("email", cmd.Email),
		slog.String("handler", "SeedSuperAdmin"),
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

	hashedPassword, err := h.passwordMgr.ValidateAndHashNewPassword(rawPassword)
	if err != nil {
		logger.Warn("password_policy_violation", slog.Any("error", err))
		return err
	}

	uidVO, err := h.idGen.GenerateUserID()
	if err != nil {
		logger.Error("id_generation_failed", slog.Any("error", err))
		return err
	}

	now := h.clock.Now()

	user, err := h.registrationSvc.RegisterNewSuperAdmin(ctx, uidVO, email, hashedPassword, now)
	if err != nil {
		logger.Warn("registration_domain_denied", slog.Any("error", err))
		return err
	}

	if err := h.userRepo.Save(ctx, user); err != nil {
		logger.Error("database_save_failed", slog.Any("error", err))
		return err
	}

	h.dispatcher.Dispatch(ctx, user.CollectEvents())

	logger.Info("super_admin_seeded_successfully",
		slog.String("user_id", user.ID().String()),
	)

	return nil
}
