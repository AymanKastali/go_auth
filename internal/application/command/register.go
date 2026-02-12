package command

import (
	"context"
	"log/slog"

	"go_auth/internal/application"
	"go_auth/internal/domain"
)

type IRegisterHandler interface {
	Handle(ctx context.Context, cmd RegisterUserCommand) (RegisterUserResponse, error)
}

type registerHandler struct {
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

func NewRegisterHandler(
	userRepo domain.IUserRepository,
	registrationSvc domain.IRegistrationService,
	passwordMgr domain.IPasswordManager,
	idGen domain.IIDGenerator,
	clock domain.IClock,
	dispatcher IEventDispatcher,
	accountManager domain.IUserAccountManager,
	activationRepo domain.IActivationTokenRepository,
	emailSvc IEmailService,
) IRegisterHandler {
	return &registerHandler{
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

func (h *registerHandler) Handle(ctx context.Context, cmd RegisterUserCommand) (RegisterUserResponse, error) {
	logger := application.GetLogger(ctx).With(
		slog.String("email", cmd.Email),
		slog.String("handler", "Register"),
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

	uid, err := h.idGen.GenerateUserID()
	if err != nil {
		logger.Error("id_generation_failed", slog.Any("error", err))
		return ZeroRegisterUserResponse, err
	}

	hashed, err := h.passwordMgr.ValidateAndHashNewPassword(rawPass)
	if err != nil {
		logger.Warn("password_policy_violation", slog.Any("error", err))
		return ZeroRegisterUserResponse, err
	}

	now := h.clock.Now()

	user, err := h.registrationSvc.RegisterNewMember(ctx, uid, email, hashed, now)
	if err != nil {
		logger.Warn("registration_domain_denied", slog.Any("error", err))
		return ZeroRegisterUserResponse, err
	}

	if err := h.userRepo.Save(ctx, user); err != nil {
		logger.Error("database_save_failed", slog.Any("error", err))
		return ZeroRegisterUserResponse, err
	}

	h.dispatcher.Dispatch(ctx, user.CollectEvents())

	if !user.IsActive() && h.activationRepo != nil {
		rawToken, activationToken, err := h.accountManager.InitiateActivation(user, now)
		if err != nil {
			logger.Error("activation_initiation_failed", slog.Any("error", err))
			return ZeroRegisterUserResponse, err
		}

		if err := h.activationRepo.Save(ctx, activationToken); err != nil {
			logger.Error("activation_token_save_failed", slog.Any("error", err))
			return ZeroRegisterUserResponse, err
		}

		h.dispatcher.Dispatch(ctx, activationToken.CollectEvents())

		if err := h.emailSvc.SendActivationLink(user.Email().String(), rawToken.String()); err != nil {
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
