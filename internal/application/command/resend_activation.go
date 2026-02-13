package command

import (
	"context"
	"log/slog"

	"go_auth/internal/application"
	"go_auth/internal/domain"
)

type IResendActivationHandler interface {
	Handle(ctx context.Context, cmd ResendActivationCommand) error
}

type resendActivationHandler struct {
	userRepo            domain.IUserRepository
	activationRepo      domain.IActivationTokenRepository
	initiateActivation domain.IInitiateActivation
	emailSvc            IEmailService
	txManager           ITransactionManager
	clock               domain.IClock
	dispatcher          IEventDispatcher
}

func NewResendActivationHandler(
	userRepo domain.IUserRepository,
	activationRepo domain.IActivationTokenRepository,
	initiateActivation domain.IInitiateActivation,
	emailSvc IEmailService,
	txManager ITransactionManager,
	clock domain.IClock,
	dispatcher IEventDispatcher,
) IResendActivationHandler {
	return &resendActivationHandler{
		userRepo:            userRepo,
		activationRepo:      activationRepo,
		initiateActivation: initiateActivation,
		emailSvc:            emailSvc,
		txManager:           txManager,
		clock:               clock,
		dispatcher:          dispatcher,
	}
}

func (h *resendActivationHandler) Handle(ctx context.Context, cmd ResendActivationCommand) error {
	logger := application.GetLogger(ctx).With(
		slog.String("email", cmd.Email),
		slog.String("handler", "ResendActivation"),
	)

	email, err := domain.NewEmail(cmd.Email)
	if err != nil {
		logger.Warn("invalid_email_format", slog.Any("error", err))
		return err
	}

	user, err := h.userRepo.FindByEmail(ctx, email)
	if err != nil {
		logger.Error("user_lookup_failed", slog.Any("error", err))
		return err
	}

	if user == nil {
		logger.Info("resend_activation_no_user")
		return nil
	}

	if user.IsActive() {
		return domain.ErrUserAlreadyActive
	}

	now := h.clock.Now()

	var rawToken string
	var token *domain.ActivationToken

	err = h.txManager.WithTransaction(ctx, func(txCtx context.Context) error {
		if err := h.activationRepo.RevokeAllForUser(txCtx, user.ID()); err != nil {
			return err
		}

		raw, activationToken, err := h.initiateActivation.Initiate(user, now)
		if err != nil {
			return err
		}

		rawToken = raw
		token = activationToken

		return h.activationRepo.Save(txCtx, activationToken)
	})

	if err != nil {
		logger.Error("resend_activation_failed", slog.Any("error", err))
		return err
	}

	h.dispatcher.Dispatch(ctx, token.CollectEvents())

	if err := h.emailSvc.SendActivationLink(user.Email().String(), rawToken); err != nil {
		logger.Error("activation_email_send_failed", slog.Any("error", err))
		return err
	}

	logger.Info("resend_activation_success")

	return nil
}
