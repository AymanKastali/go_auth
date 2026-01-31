package application

import (
	"context"
	"go_auth/internal/core/domain"
	"log/slog"
)

// --- Register Use Case ---
type registerUseCase struct {
	userRepo        domain.IUserRepository
	registrationSvc domain.IRegistrationService
	passwordMgr     domain.IPasswordManager
	idGen           domain.IIDGenerator
	clock           domain.IClock
	dispatcher      IEventDispatcher
}

func NewRegisterUseCase(
	userRepo domain.IUserRepository,
	registrationSvc domain.IRegistrationService,
	passwordMgr domain.IPasswordManager,
	idGen domain.IIDGenerator,
	clock domain.IClock,
	dispatcher IEventDispatcher,
) IRegisterUseCase {
	return &registerUseCase{
		userRepo:        userRepo,
		registrationSvc: registrationSvc,
		passwordMgr:     passwordMgr,
		idGen:           idGen,
		clock:           clock,
		dispatcher:      dispatcher,
	}
}

func (uc *registerUseCase) Execute(ctx context.Context, cmd RegisterUserCommand) (RegisterUserResponse, error) {
	logger := GetLogger(ctx).With(
		slog.String("email", cmd.Email),
		slog.String("use_case", "Register"),
	)

	email, err := domain.NewEmail(cmd.Email)
	if err != nil {
		logger.Warn("invalid_email_format", slog.Any("error", err))
		return ZeroRegisterUserResponse, err
	}

	rawPass, err := domain.NewRawPassword(cmd.Password)
	if err != nil {
		logger.Warn("invalid_password_format", slog.Any("error", err))
		return ZeroRegisterUserResponse, err
	}

	uid, err := uc.idGen.GenerateUserID()
	if err != nil {
		logger.Error("id_generation_failed", slog.Any("error", err))
		return ZeroRegisterUserResponse, err
	}

	hashed, err := uc.passwordMgr.ValidateAndHashNewPassword(rawPass)
	if err != nil {
		logger.Warn("password_policy_violation", slog.Any("error", err))
		return ZeroRegisterUserResponse, err
	}

	now := uc.clock.Now()

	user, err := uc.registrationSvc.RegisterNewMember(ctx, uid, email, hashed, now)
	if err != nil {
		logger.Warn("registration_domain_denied", slog.Any("error", err))
		return ZeroRegisterUserResponse, err
	}

	if err := uc.userRepo.Save(ctx, user); err != nil {
		logger.Error("database_save_failed", slog.Any("error", err))
		return ZeroRegisterUserResponse, err
	}

	uc.dispatcher.Dispatch(ctx, user.CollectEvents())

	logger.Info("register_success", slog.String("user_id", user.ID().String()))

	return RegisterUserResponse{
		UserID: user.ID().String(),
		Email:  user.Email().String(),
	}, nil
}
