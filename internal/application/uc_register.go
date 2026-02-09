package application

import (
	"context"
	"go_auth/internal/domain"
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
	accountManager  domain.IUserAccountManager
	activationRepo  domain.IActivationTokenRepository
	emailSvc        IEmailService
}

func NewRegisterUseCase(
	userRepo domain.IUserRepository,
	registrationSvc domain.IRegistrationService,
	passwordMgr domain.IPasswordManager,
	idGen domain.IIDGenerator,
	clock domain.IClock,
	dispatcher IEventDispatcher,
	accountManager domain.IUserAccountManager,
	activationRepo domain.IActivationTokenRepository,
	emailSvc IEmailService,
) IRegisterUseCase {
	return &registerUseCase{
		userRepo:        userRepo,
		registrationSvc: registrationSvc,
		passwordMgr:     passwordMgr,
		idGen:           idGen,
		clock:           clock,
		dispatcher:      dispatcher,
		accountManager:  accountManager,
		activationRepo:  activationRepo,
		emailSvc:        emailSvc,
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

	// If user requires email activation, initiate the activation flow
	if !user.IsActive() && uc.activationRepo != nil {
		rawToken, activationToken, err := uc.accountManager.InitiateActivation(user, now)
		if err != nil {
			logger.Error("activation_initiation_failed", slog.Any("error", err))
			return ZeroRegisterUserResponse, err
		}

		if err := uc.activationRepo.Save(ctx, activationToken); err != nil {
			logger.Error("activation_token_save_failed", slog.Any("error", err))
			return ZeroRegisterUserResponse, err
		}

		uc.dispatcher.Dispatch(ctx, activationToken.CollectEvents())

		if err := uc.emailSvc.SendActivationLink(user.Email().String(), rawToken.String()); err != nil {
			logger.Error("activation_email_send_failed", slog.Any("error", err))
			return ZeroRegisterUserResponse, err
		}
	}

	logger.Info("register_success", slog.String("user_id", user.ID().String()))

	return RegisterUserResponse{
		UserID: user.ID().String(),
		Email:  user.Email().String(),
	}, nil
}
